import jwt from "jsonwebtoken";
import { SignOptions } from "jsonwebtoken";
import { randomUUID } from "crypto";
import { RedisLock } from "../utility/lockHelper";
import { SessionStore } from "./sessionStore";

const DEFAULT_REFRESH_TTL_SECONDS = 60 * 60 * 24 * 7;
const SESSION_TTL_FALLBACK_SECONDS = 3600;
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
  userId: string;
  email: string;
  sessionId?: string;
}

export interface TokenStore {
  get(key: string): Promise<string | null>;
  set?(key: string, value: string, expiry?: number): Promise<void>;
  del?(key: string): Promise<void>;
  compareAndSet?(
    key: string,
    expected: string,
    value: string,
    expiry?: number
  ): Promise<boolean>;
}

export interface RefreshServiceOptions {
  tokenStore: TokenStore;
  accessTokenSecret: string;
  redisClient: any;
  refreshTokenSecret: string;
  accessTokenExpiry: SignOptions["expiresIn"];
  rotateRefreshTokens?: boolean;
  refreshTokenExpiry?: string | number;
}

export interface RefreshResult {
  accessToken: string;
  refreshToken?: string;
}

export class RefreshService {
  private readonly tokenStore: TokenStore;
  private readonly accessTokenSecret: string;
  private readonly refreshTokenSecret: string;
  private readonly accessTokenExpiry: SignOptions["expiresIn"];
  private readonly rotateRefreshTokens: boolean;
  private readonly refreshTokenExpiry: string | number;
  private readonly lock: RedisLock;
  private readonly sessionStore: SessionStore;

  constructor(options: RefreshServiceOptions) {
    this.tokenStore = options.tokenStore;
    this.accessTokenSecret = options.accessTokenSecret;
    this.refreshTokenSecret = options.refreshTokenSecret;
    this.accessTokenExpiry = options.accessTokenExpiry ?? "15m";
    this.rotateRefreshTokens = options.rotateRefreshTokens ?? false;
    this.refreshTokenExpiry = options.refreshTokenExpiry ?? "7d";
    this.lock = new RedisLock(options.redisClient);
    this.sessionStore = new SessionStore(options.redisClient);
  }

  async generateRefreshToken(payload: RefreshTokenPayload): Promise<string> {
    if (!payload.userId) {
      throw new Error("generateRefreshToken: payload.userId is missing");
    }

    const sessionId = payload.sessionId ?? randomUUID();
    const token = this.signRefreshToken({
      userId: payload.userId,
      email: payload.email,
      sessionId,
    });

    if (this.tokenStore.set) {
      await this.tokenStore.set(
        this.refreshKey(payload.userId, sessionId),
        token,
        this.refreshTokenTtlSeconds()
      );
    }

    return token;
  }

  async refresh(refreshToken?: string): Promise<RefreshResult> {
    if (!refreshToken) {
      throw new MissingTokenError();
    }

    const decoded = this.verifyRefreshToken(refreshToken);
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
        decoded
      );
      const newAccessToken = this.signAccessToken(decoded);

      await this.persistSessionToken(
        decoded.userId,
        decoded.sessionId,
        newAccessToken
      );

      return {
        accessToken: newAccessToken,
        refreshToken: newRefreshToken ?? refreshToken,
      };
    } finally {
      await this.lock.release(lockKey, lockValue);
    }
  }

  private async rotateTokenIfEnabled(
    key: string,
    currentRefreshToken: string,
    decoded: Required<Pick<RefreshTokenPayload, "userId" | "email" | "sessionId">>
  ): Promise<string | undefined> {
    if (!this.rotateRefreshTokens) {
      return undefined;
    }

    if (!this.tokenStore.compareAndSet) {
      throw new Error("TokenStore must implement compareAndSet for atomic refresh rotation");
    }

    const newRefreshToken = this.signRefreshToken(decoded);
    const rotated = await this.tokenStore.compareAndSet(
      key,
      currentRefreshToken,
      newRefreshToken,
      this.refreshTokenTtlSeconds()
    );

    if (!rotated) {
      await this.revokeRefreshFamily(decoded.userId, decoded.sessionId);
      throw new InvalidTokenError("Concurrent refresh detected");
    }

    return newRefreshToken;
  }

  private verifyRefreshToken(
    refreshToken: string
  ): Required<Pick<RefreshTokenPayload, "userId" | "email" | "sessionId">> {
    let decoded: RefreshTokenPayload;

    try {
      decoded = jwt.verify(
        refreshToken,
        this.refreshTokenSecret
      ) as RefreshTokenPayload;
    } catch {
      throw new InvalidTokenError();
    }

    if (!decoded.userId || !decoded.email || !decoded.sessionId) {
      throw new InvalidTokenError();
    }

    return {
      userId: decoded.userId,
      email: decoded.email,
      sessionId: decoded.sessionId,
    };
  }

  private signRefreshToken(
    payload: Required<Pick<RefreshTokenPayload, "userId" | "email" | "sessionId">>
  ): string {
    return jwt.sign(
      { ...payload, jti: randomUUID() },
      this.refreshTokenSecret,
      { expiresIn: this.refreshTokenExpiry as SignOptions["expiresIn"] }
    );
  }

  private signAccessToken(
    payload: Required<Pick<RefreshTokenPayload, "userId" | "email" | "sessionId">>
  ): string {
    return jwt.sign(payload, this.accessTokenSecret, {
      expiresIn: this.accessTokenExpiry as SignOptions["expiresIn"],
    });
  }

  private async persistSessionToken(
    userId: string,
    sessionId: string,
    token: string
  ): Promise<void> {
    const decoded = jwt.decode(token) as { exp?: number } | null;
    const now = Math.floor(Date.now() / 1000);
    const ttl = decoded?.exp
      ? Math.max(decoded.exp - now, 1)
      : SESSION_TTL_FALLBACK_SECONDS;

    await this.sessionStore.updateToken(userId, sessionId, token, ttl);
  }

  private async revokeRefreshFamily(
    userId: string,
    sessionId: string
  ): Promise<void> {
    if (this.tokenStore.del) {
      await this.tokenStore.del(this.refreshKey(userId, sessionId));
    }

    await this.sessionStore.revoke(userId, sessionId);
  }

  private refreshTokenTtlSeconds(): number {
    if (typeof this.refreshTokenExpiry === "number") {
      return this.refreshTokenExpiry;
    }

    const match = /^(\d+)([smhd])$/.exec(this.refreshTokenExpiry);
    if (!match) {
      return DEFAULT_REFRESH_TTL_SECONDS;
    }

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

  private lockKey(userId: string, sessionId: string): string {
    return `lock:${userId}:${sessionId}`;
  }
}
