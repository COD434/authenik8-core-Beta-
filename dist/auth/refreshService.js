"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.RefreshService = exports.InvalidTokenError = exports.MissingTokenError = void 0;
const crypto_1 = require("crypto");
const jwk_1 = require("./jwk");
const sessionStore_1 = require("./sessionStore");
const lockHelper_1 = require("../utility/lockHelper");
const DEFAULT_REFRESH_TTL_SECONDS = 60 * 60 * 24 * 7;
const REFRESH_LOCK_TTL_MS = 5000;
class MissingTokenError extends Error {
    constructor(message = "Missing Token") {
        super(message);
        this.name = "MissingTokenError";
    }
}
exports.MissingTokenError = MissingTokenError;
class InvalidTokenError extends Error {
    constructor(message = "Invalid refresh token") {
        super(message);
        this.name = "InvalidTokenError";
    }
}
exports.InvalidTokenError = InvalidTokenError;
class RefreshService {
    constructor(options) {
        this.tokenStore = options.tokenStore;
        this.redisClient = options.redisClient;
        this.accessTokenSigner = options.accessTokenSigner;
        this.rotateRefreshTokens = options.rotateRefreshTokens ?? false;
        this.refreshTokenExpiry = options.refreshTokenExpiry ?? "7d";
        this.lock = new lockHelper_1.RedisLock(options.redisClient);
        this.sessionStore = new sessionStore_1.SessionStore(options.redisClient);
        this.refreshKeys = new jwk_1.JwtKeyRing({
            legacySecret: options.refreshTokenSecret,
            issuer: options.issuer,
            audience: options.audience,
        });
    }
    async generateRefreshToken(payload) {
        if (!payload.userId) {
            throw new Error("generateRefreshToken: payload.userId is missing");
        }
        const tokenPayload = {
            userId: payload.userId,
            email: payload.email,
            sessionId: payload.sessionId ?? (0, crypto_1.randomUUID)(),
        };
        const token = await this.signRefreshToken(tokenPayload);
        if (this.tokenStore.set) {
            await this.tokenStore.set(this.refreshKey(tokenPayload.userId, tokenPayload.sessionId), token, this.refreshTokenTtlSeconds());
            await this.trackRefreshFamily(tokenPayload.userId, tokenPayload.sessionId);
        }
        return token;
    }
    async refresh(refreshToken) {
        if (!refreshToken)
            throw new MissingTokenError();
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
            const newRefreshToken = await this.rotateTokenIfEnabled(key, refreshToken, decoded);
            const newAccessToken = await this.accessTokenSigner(decoded);
            return {
                accessToken: newAccessToken,
                refreshToken: newRefreshToken ?? refreshToken,
            };
        }
        finally {
            await this.lock.release(lockKey, lockValue);
        }
    }
    async revokeSession(userId, sessionId) {
        await this.revokeRefreshFamily(userId, sessionId);
    }
    async revokeAllSessions(userId, fallbackSessionIds = []) {
        const indexedFamilies = this.redisClient?.hgetall
            ? await this.redisClient.hgetall(this.refreshFamilyIndexKey(userId))
            : null;
        const sessionIds = new Set([
            ...fallbackSessionIds,
            ...Object.keys(indexedFamilies || {}),
        ]);
        if (this.tokenStore.del) {
            await Promise.all([...sessionIds].map((sessionId) => this.tokenStore.del(this.refreshKey(userId, sessionId))));
        }
        if (this.redisClient?.del) {
            await this.redisClient.del(this.refreshFamilyIndexKey(userId));
        }
        await this.sessionStore.revokeAll(userId);
    }
    async rotateTokenIfEnabled(key, currentRefreshToken, decoded) {
        if (!this.rotateRefreshTokens)
            return undefined;
        if (!this.tokenStore.compareAndSet) {
            throw new Error("TokenStore must implement compareAndSet for atomic refresh rotation");
        }
        const newRefreshToken = await this.signRefreshToken(decoded);
        const rotated = await this.tokenStore.compareAndSet(key, currentRefreshToken, newRefreshToken, this.refreshTokenTtlSeconds());
        if (!rotated) {
            await this.revokeRefreshFamily(decoded.userId, decoded.sessionId);
            throw new InvalidTokenError("Concurrent refresh detected");
        }
        return newRefreshToken;
    }
    async verifyRefreshToken(refreshToken) {
        try {
            const decoded = await this.refreshKeys.verify(refreshToken, "refresh");
            if (!decoded.userId || !decoded.email || !decoded.sessionId) {
                throw new InvalidTokenError();
            }
            return {
                userId: decoded.userId,
                email: decoded.email,
                sessionId: decoded.sessionId,
            };
        }
        catch (error) {
            if (error instanceof InvalidTokenError)
                throw error;
            throw new InvalidTokenError();
        }
    }
    signRefreshToken(payload) {
        return this.refreshKeys.sign(payload, {
            expiresIn: this.refreshTokenExpiry,
            tokenUse: "refresh",
        });
    }
    async revokeRefreshFamily(userId, sessionId) {
        if (this.tokenStore.del) {
            await this.tokenStore.del(this.refreshKey(userId, sessionId));
        }
        if (this.redisClient?.hdel) {
            await this.redisClient.hdel(this.refreshFamilyIndexKey(userId), sessionId);
        }
        await this.sessionStore.revoke(userId, sessionId);
    }
    async trackRefreshFamily(userId, sessionId) {
        if (!this.redisClient?.hset)
            return;
        const key = this.refreshFamilyIndexKey(userId);
        await this.redisClient.hset(key, sessionId, "1");
        if (this.redisClient.expire) {
            await this.redisClient.expire(key, this.refreshTokenTtlSeconds());
        }
    }
    refreshTokenTtlSeconds() {
        if (typeof this.refreshTokenExpiry === "number") {
            return this.refreshTokenExpiry;
        }
        const match = /^(\d+)([smhd])$/.exec(this.refreshTokenExpiry);
        if (!match)
            return DEFAULT_REFRESH_TTL_SECONDS;
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
    refreshKey(userId, sessionId) {
        return `refresh:${userId}:${sessionId}`;
    }
    refreshFamilyIndexKey(userId) {
        return `refresh-families:${userId}`;
    }
    lockKey(userId, sessionId) {
        return `lock:${userId}:${sessionId}`;
    }
}
exports.RefreshService = RefreshService;
//# sourceMappingURL=refreshService.js.map