import { randomUUID } from "crypto";
import { JwtKeyRing } from "./jwk";
import { SessionStore } from "./sessionStore";
import { RedisLock } from "../utility/lockHelper";

const DEFAULT_REFRESH_TTL_SECONDS = 60 * 60 * 24 * 7;
const REFRESH_LOCK_TTL_MS = 5000;

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
}

export interface RefreshResult {
  accessToken: string;
  refreshToken?: string;
}

export class RefreshService {
  private readonly tokenStore: TokenStore;
  private readonly accessTokenSigner: RefreshServiceOptions["accessTokenSigner"];
  private readonly rotateRefreshTokens: boolean;
  private readonly refreshTokenExpiry: string | number;
  private readonly lock: RedisLock;
  private readonly sessionStore: SessionStore;
  private readonly refreshKeys: JwtKeyRing;
  private readonly redisClient: any;

  constructor(options: RefreshServiceOptions) {
    this.tokenStore = options.tokenStore;
    this.redisClient = options.redisClient;
    this.accessTokenSigner = options.accessTokenSigner;
    this.rotateRefreshTokens = options.rotateRefreshTokens ?? false;
    this.refreshTokenExpiry = options.refreshTokenExpiry ?? "7d";
    this.lock = new RedisLock(options.redisClient);
    this.sessionStore = new SessionStore(options.redisClient);
    this.refreshKeys = new JwtKeyRing({
      legacySecret: options.refreshTokenSecret,
      issuer: options.issuer,
      audience: options.audience,
    });
  }

  async generateRefreshToken(payload: RefreshTokenPayload): Promise<string> {
    if (!payload.userId) {
      throw new Error("generateRefreshToken: payload.userId is missing");
    }

    const tokenPayload: RequiredRefreshPayload = {
      userId: payload.userId,
      email: payload.email,
      sessionId: payload.sessionId ?? randomUUID(),
    };
    const token = await this.signRefreshToken(tokenPayload);

    if (this.tokenStore.set) {
      await this.tokenStore.set(
        this.refreshKey(tokenPayload.userId, tokenPayload.sessionId),
        token,
        this.refreshTokenTtlSeconds(),
      );
      await this.trackRefreshFamily(tokenPayload.userId, tokenPayload.sessionId);
    }

    return token;
  }

  async refresh(refreshToken?: string): Promise<RefreshResult> {
    if (!refreshToken) throw new MissingTokenError();

    const decoded = await this.verifyRefreshToken(refreshToken);
    const lockKey = this.lockKey(decoded.userId, decoded.sessionId);
    const lockValue = await this.lock.acquire(lockKey, REFRESH_LOCK_TTL_MS);

    if (!lockValue) {
      throw new InvalidTokenError("Concurrent refresh detected");
    }

    try {
      const key = this.refreshKey(decoded.userId, decoded.sessionId);
      const storedToken = await this.tokenStore.get(key);

      if (storedToken !== refreshToken) {
        await this.revokeRefreshFamily(decoded.userId, decoded.sessionId);
        throw new InvalidTokenError();
      }

      const newRefreshToken = await this.rotateTokenIfEnabled(
        key,
        refreshToken,
        decoded,
      );
      const newAccessToken = await this.accessTokenSigner(decoded);

      return {
        accessToken: newAccessToken,
        refreshToken: newRefreshToken ?? refreshToken,
      };
    } finally {
      await this.lock.release(lockKey, lockValue);
    }
  }

  async revokeSession(userId: string, sessionId: string): Promise<void> {
    await this.revokeRefreshFamily(userId, sessionId);
  }

  async revokeAllSessions(
    userId: string,
    fallbackSessionIds: string[] = [],
  ): Promise<void> {
    const indexedFamilies = this.redisClient?.hgetall
      ? await this.redisClient.hgetall(this.refreshFamilyIndexKey(userId))
      : null;
    const sessionIds = new Set([
      ...fallbackSessionIds,
      ...Object.keys(indexedFamilies || {}),
    ]);

    if (this.tokenStore.del) {
      await Promise.all(
        [...sessionIds].map((sessionId) =>
          this.tokenStore.del!(this.refreshKey(userId, sessionId)),
        ),
      );
    }
    if (this.redisClient?.del) {
      await this.redisClient.del(this.refreshFamilyIndexKey(userId));
    }
    await this.sessionStore.revokeAll(userId);
  }

  private async rotateTokenIfEnabled(
    key: string,
    currentRefreshToken: string,
    decoded: RequiredRefreshPayload,
  ): Promise<string | undefined> {
    if (!this.rotateRefreshTokens) return undefined;
    if (!this.tokenStore.compareAndSet) {
      throw new Error("TokenStore must implement compareAndSet for atomic refresh rotation");
    }

    const newRefreshToken = await this.signRefreshToken(decoded);
    const rotated = await this.tokenStore.compareAndSet(
      key,
      currentRefreshToken,
      newRefreshToken,
      this.refreshTokenTtlSeconds(),
    );

    if (!rotated) {
      await this.revokeRefreshFamily(decoded.userId, decoded.sessionId);
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

      if (!decoded.userId || !decoded.email || !decoded.sessionId) {
        throw new InvalidTokenError();
      }

      return {
        userId: decoded.userId,
        email: decoded.email,
        sessionId: decoded.sessionId,
      };
    } catch (error) {
      if (error instanceof InvalidTokenError) throw error;
      throw new InvalidTokenError();
    }
  }

  private signRefreshToken(payload: RequiredRefreshPayload): Promise<string> {
    return this.refreshKeys.sign(payload, {
      expiresIn: this.refreshTokenExpiry,
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
    if (typeof this.refreshTokenExpiry === "number") {
      return this.refreshTokenExpiry;
    }

    const match = /^(\d+)([smhd])$/.exec(this.refreshTokenExpiry);
    if (!match) return DEFAULT_REFRESH_TTL_SECONDS;
    const amount = Number(match[1]);

    switch (match[2]) {
      case "s":
        return amount;
      case "m":
        return amount * 60;
      case "h":
        return amount * 60 * 60;
      case "d":
        return amount * 60 * 60 * 24;
      default:
        return DEFAULT_REFRESH_TTL_SECONDS;
    }
  }

  private refreshKey(userId: string, sessionId: string): string {
    return `refresh:${userId}:${sessionId}`;
  }

  private refreshFamilyIndexKey(userId: string): string {
    return `refresh-families:${userId}`;
  }

  private lockKey(userId: string, sessionId: string): string {
    return `lock:${userId}:${sessionId}`;
  }
}
