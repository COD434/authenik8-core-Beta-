"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.RefreshService = exports.InvalidTokenError = exports.MissingTokenError = void 0;
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const crypto_1 = require("crypto");
const lockHelper_1 = require("../utility/lockHelper");
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
        this.redisClient = options.redisClient;
    }
    async persistSessionToken(userId, token) {
        const decoded = jsonwebtoken_1.default.decode(token);
        const now = Math.floor(Date.now() / 1000);
        const ttl = decoded?.exp ? Math.max(decoded.exp - now, 1) : 3600;
        await this.redisClient.set(`session:${userId}`, token, "EX", ttl);
    }
    async generateRefreshToken(payload) {
        if (!payload.userId)
            throw new Error("generateRefreshToken: payload.userId is missing");
        const token = jsonwebtoken_1.default.sign({ ...payload, jti: (0, crypto_1.randomUUID)(), }, this.refreshTokenSecret, {
            expiresIn: this.refreshTokenExpiry,
        });
        if (this.tokenStore.set) {
            await this.tokenStore.set(`refresh:${payload.userId}`, token, 60 * 60 * 24 * 7);
        }
        return token;
    }
    async refresh(refreshToken) {
        if (!refreshToken) {
            throw new MissingTokenError();
        }
        let decoded;
        try {
            decoded = jsonwebtoken_1.default.verify(refreshToken, this.refreshTokenSecret);
        }
        catch (err) {
            throw new InvalidTokenError();
        }
        const lockKey = `lock:${decoded.userId}`;
        const lockValue = await this.lock.acquire(lockKey, 5000);
        let hasLock = !!lockValue;
        if (!lockValue) {
            throw new InvalidTokenError("Concurrent refresh detected");
        }
        try {
            const key = `refresh:${decoded.userId}`;
            const storedToken = await this.tokenStore.get(key);
            if (!storedToken || storedToken !== refreshToken) {
                throw new InvalidTokenError();
            }
            const newAccessToken = jsonwebtoken_1.default.sign({ userId: decoded.userId, email: decoded.email }, this.accessTokenSecret, { expiresIn: this.accessTokenExpiry });
            await this.persistSessionToken(decoded.userId, newAccessToken);
            let newRefreshToken;
            if (this.rotateRefreshTokens && this.tokenStore.set) {
                const key = `refresh:${decoded.userId}`;
                newRefreshToken = jsonwebtoken_1.default.sign({ userId: decoded.userId, email: decoded.email, jti: (0, crypto_1.randomUUID)(), }, this.refreshTokenSecret, { expiresIn: this.refreshTokenExpiry });
                if (!this.tokenStore.getset) {
                    throw new Error("TokenStore must implement getset for atomic refresh rotation");
                }
                const PreviousToken = await this.tokenStore.getset(key, newRefreshToken, 60 * 60 * 24 * 7);
                if (PreviousToken !== refreshToken && PreviousToken !== storedToken) {
                    throw new InvalidTokenError("Concurrent refresh detected");
                }
            }
            return {
                accessToken: newAccessToken,
                refreshToken: newRefreshToken ?? refreshToken
            };
        }
        finally {
            if (hasLock && lockValue)
                await this.lock.release(lockKey, lockValue);
        }
    }
}
exports.RefreshService = RefreshService;
//# sourceMappingURL=refreshService.js.map