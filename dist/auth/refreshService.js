"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.RefreshService = exports.InvalidTokenError = exports.MissingTokenError = void 0;
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const crypto_1 = require("crypto");
const lockHelper_1 = require("../utility/lockHelper");
const sessionStore_1 = require("./sessionStore");
const DEFAULT_REFRESH_TTL_SECONDS = 60 * 60 * 24 * 7;
const SESSION_TTL_FALLBACK_SECONDS = 3600;
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
        this.accessTokenSecret = options.accessTokenSecret;
        this.refreshTokenSecret = options.refreshTokenSecret;
        this.accessTokenExpiry = options.accessTokenExpiry ?? "15m";
        this.rotateRefreshTokens = options.rotateRefreshTokens ?? false;
        this.refreshTokenExpiry = options.refreshTokenExpiry ?? "7d";
        this.lock = new lockHelper_1.RedisLock(options.redisClient);
        this.sessionStore = new sessionStore_1.SessionStore(options.redisClient);
    }
    async generateRefreshToken(payload) {
        if (!payload.userId) {
            throw new Error("generateRefreshToken: payload.userId is missing");
        }
        const sessionId = payload.sessionId ?? (0, crypto_1.randomUUID)();
        const token = this.signRefreshToken({
            userId: payload.userId,
            email: payload.email,
            sessionId,
        });
        if (this.tokenStore.set) {
            await this.tokenStore.set(this.refreshKey(payload.userId, sessionId), token, this.refreshTokenTtlSeconds());
        }
        return token;
    }
    async refresh(refreshToken) {
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
            const newRefreshToken = await this.rotateTokenIfEnabled(key, refreshToken, decoded);
            const newAccessToken = this.signAccessToken(decoded);
            await this.persistSessionToken(decoded.userId, decoded.sessionId, newAccessToken);
            return {
                accessToken: newAccessToken,
                refreshToken: newRefreshToken ?? refreshToken,
            };
        }
        finally {
            await this.lock.release(lockKey, lockValue);
        }
    }
    async rotateTokenIfEnabled(key, currentRefreshToken, decoded) {
        if (!this.rotateRefreshTokens) {
            return undefined;
        }
        if (!this.tokenStore.compareAndSet) {
            throw new Error("TokenStore must implement compareAndSet for atomic refresh rotation");
        }
        const newRefreshToken = this.signRefreshToken(decoded);
        const rotated = await this.tokenStore.compareAndSet(key, currentRefreshToken, newRefreshToken, this.refreshTokenTtlSeconds());
        if (!rotated) {
            await this.revokeRefreshFamily(decoded.userId, decoded.sessionId);
            throw new InvalidTokenError("Concurrent refresh detected");
        }
        return newRefreshToken;
    }
    verifyRefreshToken(refreshToken) {
        let decoded;
        try {
            decoded = jsonwebtoken_1.default.verify(refreshToken, this.refreshTokenSecret);
        }
        catch {
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
    signRefreshToken(payload) {
        return jsonwebtoken_1.default.sign({ ...payload, jti: (0, crypto_1.randomUUID)() }, this.refreshTokenSecret, { expiresIn: this.refreshTokenExpiry });
    }
    signAccessToken(payload) {
        return jsonwebtoken_1.default.sign(payload, this.accessTokenSecret, {
            expiresIn: this.accessTokenExpiry,
        });
    }
    async persistSessionToken(userId, sessionId, token) {
        const decoded = jsonwebtoken_1.default.decode(token);
        const now = Math.floor(Date.now() / 1000);
        const ttl = decoded?.exp
            ? Math.max(decoded.exp - now, 1)
            : SESSION_TTL_FALLBACK_SECONDS;
        await this.sessionStore.updateToken(userId, sessionId, token, ttl);
    }
    async revokeRefreshFamily(userId, sessionId) {
        if (this.tokenStore.del) {
            await this.tokenStore.del(this.refreshKey(userId, sessionId));
        }
        await this.sessionStore.revoke(userId, sessionId);
    }
    refreshTokenTtlSeconds() {
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
    refreshKey(userId, sessionId) {
        return `refresh:${userId}:${sessionId}`;
    }
    lockKey(userId, sessionId) {
        return `lock:${userId}:${sessionId}`;
    }
}
exports.RefreshService = RefreshService;
//# sourceMappingURL=refreshService.js.map