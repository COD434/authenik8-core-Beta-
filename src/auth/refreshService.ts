import { createHash, randomUUID } from "crypto";
import { JwtKeyRing, normalizeTokenLifetime } from "./jwk";
import { SessionStore } from "./sessionStore";
import { RedisLock } from "../utility/lockHelper";
import type { AuditEmitter } from "../audit/types";
import type { SessionRiskReporter } from "../risk/types";
import {
  tokenFingerprint,
  tokenFingerprintMatches,
} from "./tokenFingerprint";
import { validateRedisKeyPrefix } from "../redis/keyNamespace";
import { containsControlCharacter } from "../utility/safeString";

const DEFAULT_REFRESH_TTL_SECONDS = 60 * 60 * 24 * 7;
const MAX_REFRESH_TTL_SECONDS = 31 * 24 * 60 * 60;
const REFRESH_LOCK_TTL_MS = 30_000;
const MAX_REFRESH_IDENTIFIER_LENGTH = 256;
const REFRESH_REVOCATION_BATCH_SIZE = 100;
const MAX_FALLBACK_SESSION_IDS = 10_000;
const TOKEN_FINGERPRINT_PATTERN = /^[A-Za-z0-9_-]{43}$/;

const validateRefreshIdentifier = (
  value: unknown,
  label: string,
): string => {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > MAX_REFRESH_IDENTIFIER_LENGTH ||
    containsControlCharacter(value)
  ) {
    throw new Error(
      `${label} must contain between 1 and ${MAX_REFRESH_IDENTIFIER_LENGTH} safe characters`,
    );
  }
  return value;
};

const pairDigest = (first: string, second: string): string =>
  createHash("sha256")
    .update(first)
    .update("\0")
    .update(second)
    .digest("base64url");

const refreshTokenMatches = (
  storedToken: unknown,
  presentedToken: string,
): storedToken is string => {
  if (
    typeof storedToken !== "string" ||
    storedToken.length === 0 ||
    storedToken.length > 16 * 1024
  ) {
    return false;
  }
  const expectedFingerprint = TOKEN_FINGERPRINT_PATTERN.test(storedToken)
    ? storedToken
    : tokenFingerprint(storedToken);
  return tokenFingerprintMatches(expectedFingerprint, presentedToken);
};

export class MissingTokenError extends Error {
  constructor(message = "Missing Token") {
    super(message);
    this.name = "MissingTokenError";
  }
}

export class InvalidTokenError extends Error {
  constructor(message = "Invalid refresh token") {
    super(message);
    this.name = "InvalidTokenError";
  }
}

interface RefreshTokenPayload {
  [key: string]: unknown;
  userId: string;
  email: string;
  sessionId?: string;
  tokenUse?: string;
}

type RequiredRefreshPayload = Required<
  Pick<RefreshTokenPayload, "userId" | "email" | "sessionId">
>;

export interface TokenStore {
  get(key: string): Promise<string | null>;
  set?(key: string, value: string, expiry?: number): Promise<void>;
  del?(key: string): Promise<void>;
  compareAndSet?(
    key: string,
    expected: string,
    value: string,
    expiry?: number,
  ): Promise<boolean>;
}

export interface RefreshServiceOptions {
  tokenStore: TokenStore;
  redisClient: any;
  refreshTokenSecret: string;
  accessTokenSigner: (payload: RequiredRefreshPayload) => Promise<string>;
  issuer: string;
  audience: string | string[];
  rotateRefreshTokens?: boolean;
  refreshTokenExpiry?: string | number;
  audit?: AuditEmitter;
  risk?: SessionRiskReporter;
  keyPrefix?: string;
}

export interface RefreshResult {
  accessToken: string;
  refreshToken?: string;
}

export class RefreshService {
  private readonly tokenStore: TokenStore;
  private readonly accessTokenSigner: RefreshServiceOptions["accessTokenSigner"];
  private readonly rotateRefreshTokens: boolean;
  private readonly refreshTokenTtl: number;
  private readonly lock: RedisLock;
  private readonly sessionStore: SessionStore;
  private readonly refreshKeys: JwtKeyRing;
  private readonly redisClient: any;
  private readonly audit?: AuditEmitter;
  private readonly risk?: SessionRiskReporter;
  private readonly keyPrefix: string;

  constructor(options: RefreshServiceOptions) {
    if (
      options.rotateRefreshTokens !== undefined &&
      typeof options.rotateRefreshTokens !== "boolean"
    ) {
      throw new Error("rotateRefreshTokens must be a boolean");
    }
    if (!options.tokenStore || typeof options.tokenStore.get !== "function") {
      throw new Error("TokenStore must implement get()");
    }
    if (
      options.rotateRefreshTokens === true &&
      typeof options.tokenStore.compareAndSet !== "function"
    ) {
      throw new Error(
        "TokenStore must implement compareAndSet for atomic refresh rotation",
      );
    }
    this.tokenStore = options.tokenStore;
    this.redisClient = options.redisClient;
    this.accessTokenSigner = options.accessTokenSigner;
    this.rotateRefreshTokens = options.rotateRefreshTokens ?? false;
    this.refreshTokenTtl = normalizeTokenLifetime(
      options.refreshTokenExpiry ?? "7d",
      "refreshTokenExpiry",
      60,
      MAX_REFRESH_TTL_SECONDS,
    );
    this.audit = options.audit;
    this.risk = options.risk;
    this.keyPrefix = options.keyPrefix
      ? validateRedisKeyPrefix(options.keyPrefix)
      : "";
    this.lock = new RedisLock(options.redisClient);
    this.sessionStore = new SessionStore(
      options.redisClient,
      this.scoped("sessions"),
    );
    this.refreshKeys = new JwtKeyRing({
      legacySecret: options.refreshTokenSecret,
      issuer: options.issuer,
      audience: options.audience,
    });
  }

  async generateRefreshToken(payload: RefreshTokenPayload): Promise<string> {
    const userId = validateRefreshIdentifier(
      payload.userId,
      "generateRefreshToken: payload.userId",
    );
    if (
      typeof payload.email !== "string" ||
      payload.email.length === 0 ||
      payload.email.length > 254 ||
      containsControlCharacter(payload.email)
    ) {
      throw new Error("generateRefreshToken: payload.email is invalid");
    }
    const sessionId =
      payload.sessionId === undefined
        ? randomUUID()
        : validateRefreshIdentifier(
            payload.sessionId,
            "generateRefreshToken: payload.sessionId",
          );

    const tokenPayload: RequiredRefreshPayload = {
      userId,
      email: payload.email,
      sessionId,
    };
    const token = await this.signRefreshToken(tokenPayload);

    const key = this.refreshKey(tokenPayload.userId, tokenPayload.sessionId);
    if (this.tokenStore.set) {
      await this.tokenStore.set(
        key,
        tokenFingerprint(token),
        this.refreshTokenTtlSeconds(),
      );
      try {
        await this.trackRefreshFamily(
          tokenPayload.userId,
          tokenPayload.sessionId,
        );
      } catch (error) {
        await this.tokenStore.del?.(key);
        throw error;
      }
    }
    try {
      await this.audit?.emit({
        type: "refresh_token.issued",
        severity: "info",
        outcome: "success",
        actor: { type: "system" },
        subject: { type: "user", id: tokenPayload.userId },
        sessionId: tokenPayload.sessionId,
      });
    } catch (error) {
      await this.revokeRefreshFamily(
        tokenPayload.userId,
        tokenPayload.sessionId,
      );
      throw error;
    }

    return token;
  }

  async refresh(refreshToken?: string): Promise<RefreshResult> {
    if (!refreshToken) throw new MissingTokenError();

    const decoded = await this.verifyRefreshToken(refreshToken);
    if (
      await this.risk?.isQuarantined(
        this.principal(decoded.userId, decoded.sessionId),
      )
    ) {
      throw new InvalidTokenError("Session quarantined");
    }
    const lockKey = this.lockKey(decoded.userId, decoded.sessionId);
    const lockValue = await this.lock.acquire(lockKey, REFRESH_LOCK_TTL_MS);

    if (!lockValue) {
      await this.reportConcurrentRefresh(decoded);
      throw new InvalidTokenError("Concurrent refresh detected");
    }

    try {
      const key = this.refreshKey(decoded.userId, decoded.sessionId);
      const storedToken = await this.tokenStore.get(key);

      if (!refreshTokenMatches(storedToken, refreshToken)) {
        try {
          await this.risk?.report({
            type: "refresh_replay",
            principal: this.principal(decoded.userId, decoded.sessionId),
          });
          await this.audit?.emit({
            type: "refresh_token.replay_detected",
            severity: "critical",
            outcome: "denied",
            actor: { type: "user", id: decoded.userId },
            sessionId: decoded.sessionId,
          });
        } finally {
          await this.revokeRefreshFamily(decoded.userId, decoded.sessionId);
        }
        throw new InvalidTokenError();
      }

      const newRefreshToken = await this.rotateTokenIfEnabled(
        key,
        storedToken,
        decoded,
      );
      let newAccessToken: string;
      try {
        newAccessToken = await this.accessTokenSigner(decoded);
        await this.audit?.emit({
          type: "refresh_token.rotated",
          severity: "info",
          outcome: "success",
          actor: { type: "user", id: decoded.userId },
          sessionId: decoded.sessionId,
        });
      } catch (error) {
        await this.revokeRefreshFamily(decoded.userId, decoded.sessionId);
        throw error;
      }

      return {
        accessToken: newAccessToken,
        refreshToken: newRefreshToken ?? refreshToken,
      };
    } finally {
      await this.lock.release(lockKey, lockValue);
    }
  }

  async revokeSession(userId: string, sessionId: string): Promise<void> {
    const validUserId = validateRefreshIdentifier(userId, "userId");
    const validSessionId = validateRefreshIdentifier(sessionId, "sessionId");
    await this.revokeRefreshFamily(validUserId, validSessionId);
    await this.audit?.emit({
      type: "session.revoked",
      severity: "warning",
      outcome: "success",
      actor: { type: "system" },
      subject: { type: "user", id: validUserId },
      sessionId: validSessionId,
    });
  }

  async revokeAllSessions(
    userId: string,
    fallbackSessionIds: string[] = [],
  ): Promise<void> {
    const validUserId = validateRefreshIdentifier(userId, "userId");
    if (fallbackSessionIds.length > MAX_FALLBACK_SESSION_IDS) {
      throw new Error(
        `fallbackSessionIds must not contain more than ${MAX_FALLBACK_SESSION_IDS} entries`,
      );
    }
    const validFallbackSessionIds = fallbackSessionIds.map((sessionId) =>
      validateRefreshIdentifier(sessionId, "sessionId"),
    );
    const indexedFamilies: Record<string, string> | null =
      this.redisClient?.hgetall
        ? await this.redisClient.hgetall(
            this.refreshFamilyIndexKey(validUserId),
          )
        : null;
    const sessionIds = new Set([
      ...validFallbackSessionIds,
      ...Object.keys(indexedFamilies || {}),
    ]);
    for (const sessionId of sessionIds) {
      validateRefreshIdentifier(sessionId, "indexed sessionId");
    }

    if (this.tokenStore.del) {
      const pendingSessionIds = [...sessionIds];
      for (
        let offset = 0;
        offset < pendingSessionIds.length;
        offset += REFRESH_REVOCATION_BATCH_SIZE
      ) {
        await Promise.all(
          pendingSessionIds
            .slice(offset, offset + REFRESH_REVOCATION_BATCH_SIZE)
            .map((sessionId) =>
              this.tokenStore.del!(
                this.refreshKey(validUserId, sessionId),
              ),
            ),
        );
      }
    }
    if (this.redisClient?.del) {
      await this.redisClient.del(this.refreshFamilyIndexKey(validUserId));
    }
    await this.sessionStore.revokeAll(validUserId);
    await this.audit?.emit({
      type: "session.revoked_all",
      severity: "warning",
      outcome: "success",
      actor: { type: "system" },
      subject: { type: "user", id: validUserId },
    });
  }

  private async rotateTokenIfEnabled(
    key: string,
    storedToken: string,
    decoded: RequiredRefreshPayload,
  ): Promise<string | undefined> {
    if (!this.rotateRefreshTokens) return undefined;
    if (!this.tokenStore.compareAndSet) {
      throw new Error("TokenStore must implement compareAndSet for atomic refresh rotation");
    }

    const newRefreshToken = await this.signRefreshToken(decoded);
    const rotated = await this.tokenStore.compareAndSet(
      key,
      storedToken,
      tokenFingerprint(newRefreshToken),
      this.refreshTokenTtlSeconds(),
    );

    if (!rotated) {
      try {
        await this.reportConcurrentRefresh(decoded);
      } finally {
        await this.revokeRefreshFamily(decoded.userId, decoded.sessionId);
      }
      throw new InvalidTokenError("Concurrent refresh detected");
    }

    return newRefreshToken;
  }

  private async verifyRefreshToken(
    refreshToken: string,
  ): Promise<RequiredRefreshPayload> {
    try {
      const decoded = await this.refreshKeys.verify<RefreshTokenPayload>(
        refreshToken,
        "refresh",
      );

      const userId = validateRefreshIdentifier(decoded.userId, "userId");
      const sessionId = validateRefreshIdentifier(
        decoded.sessionId,
        "sessionId",
      );
      if (
        typeof decoded.email !== "string" ||
        decoded.email.length === 0 ||
        decoded.email.length > 254 ||
        containsControlCharacter(decoded.email)
      ) {
        throw new InvalidTokenError();
      }

      return {
        userId,
        email: decoded.email,
        sessionId,
      };
    } catch (error) {
      if (error instanceof InvalidTokenError) throw error;
      throw new InvalidTokenError();
    }
  }

  private signRefreshToken(payload: RequiredRefreshPayload): Promise<string> {
    return this.refreshKeys.sign(payload, {
      expiresInSeconds: this.refreshTokenTtl,
      tokenUse: "refresh",
    });
  }

  private async revokeRefreshFamily(
    userId: string,
    sessionId: string,
  ): Promise<void> {
    if (this.tokenStore.del) {
      await this.tokenStore.del(this.refreshKey(userId, sessionId));
    }
    if (this.redisClient?.hdel) {
      await this.redisClient.hdel(this.refreshFamilyIndexKey(userId), sessionId);
    }
    await this.sessionStore.revoke(userId, sessionId);
  }

  private async trackRefreshFamily(userId: string, sessionId: string): Promise<void> {
    if (!this.redisClient?.hset) return;

    const key = this.refreshFamilyIndexKey(userId);
    await this.redisClient.hset(key, sessionId, "1");
    if (this.redisClient.expire) {
      await this.redisClient.expire(key, this.refreshTokenTtlSeconds());
    }
  }

  private refreshTokenTtlSeconds(): number {
    return this.refreshTokenTtl;
  }

  private refreshKey(userId: string, sessionId: string): string {
    return this.scoped("refresh", pairDigest(userId, sessionId));
  }

  private refreshFamilyIndexKey(userId: string): string {
    return this.scoped("refresh-families", userId);
  }

  private lockKey(userId: string, sessionId: string): string {
    return this.scoped("lock", pairDigest(userId, sessionId));
  }

  private scoped(...parts: string[]): string {
    return [this.keyPrefix, ...parts].filter(Boolean).join(":");
  }

  private principal(userId: string, sessionId: string) {
    return { kind: "human" as const, id: userId, sessionId };
  }

  private async reportConcurrentRefresh(
    decoded: RequiredRefreshPayload,
  ): Promise<void> {
    await this.risk?.report({
      type: "concurrent_refresh",
      principal: this.principal(decoded.userId, decoded.sessionId),
    });
    await this.audit?.emit({
      type: "refresh_token.concurrent_use_detected",
      severity: "warning",
      outcome: "denied",
      actor: { type: "user", id: decoded.userId },
      sessionId: decoded.sessionId,
    });
  }
}
