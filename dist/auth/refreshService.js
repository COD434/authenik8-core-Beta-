"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.RefreshService = exports.InvalidTokenError = exports.MissingTokenError = void 0;
const crypto_1 = require("crypto");
const jwk_1 = require("./jwk");
const sessionStore_1 = require("./sessionStore");
const lockHelper_1 = require("../utility/lockHelper");
const tokenFingerprint_1 = require("./tokenFingerprint");
const keyNamespace_1 = require("../redis/keyNamespace");
const safeString_1 = require("../utility/safeString");
const DEFAULT_REFRESH_TTL_SECONDS = 60 * 60 * 24 * 7;
const MAX_REFRESH_TTL_SECONDS = 31 * 24 * 60 * 60;
const REFRESH_LOCK_TTL_MS = 30000;
const MAX_REFRESH_IDENTIFIER_LENGTH = 256;
const REFRESH_REVOCATION_BATCH_SIZE = 100;
const MAX_FALLBACK_SESSION_IDS = 10000;
const TOKEN_FINGERPRINT_PATTERN = /^[A-Za-z0-9_-]{43}$/;
const validateRefreshIdentifier = (value, label) => {
    if (typeof value !== "string" ||
        value.length === 0 ||
        value.length > MAX_REFRESH_IDENTIFIER_LENGTH ||
        (0, safeString_1.containsControlCharacter)(value)) {
        throw new Error(`${label} must contain between 1 and ${MAX_REFRESH_IDENTIFIER_LENGTH} safe characters`);
    }
    return value;
};
const pairDigest = (first, second) => (0, crypto_1.createHash)("sha256")
    .update(first)
    .update("\0")
    .update(second)
    .digest("base64url");
const refreshTokenMatches = (storedToken, presentedToken) => {
    if (typeof storedToken !== "string" ||
        storedToken.length === 0 ||
        storedToken.length > 16 * 1024) {
        return false;
    }
    const expectedFingerprint = TOKEN_FINGERPRINT_PATTERN.test(storedToken)
        ? storedToken
        : (0, tokenFingerprint_1.tokenFingerprint)(storedToken);
    return (0, tokenFingerprint_1.tokenFingerprintMatches)(expectedFingerprint, presentedToken);
};
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
        if (options.rotateRefreshTokens !== undefined &&
            typeof options.rotateRefreshTokens !== "boolean") {
            throw new Error("rotateRefreshTokens must be a boolean");
        }
        if (!options.tokenStore || typeof options.tokenStore.get !== "function") {
            throw new Error("TokenStore must implement get()");
        }
        if (options.rotateRefreshTokens === true &&
            typeof options.tokenStore.compareAndSet !== "function") {
            throw new Error("TokenStore must implement compareAndSet for atomic refresh rotation");
        }
        this.tokenStore = options.tokenStore;
        this.redisClient = options.redisClient;
        this.accessTokenSigner = options.accessTokenSigner;
        this.rotateRefreshTokens = options.rotateRefreshTokens ?? false;
        this.refreshTokenTtl = (0, jwk_1.normalizeTokenLifetime)(options.refreshTokenExpiry ?? "7d", "refreshTokenExpiry", 60, MAX_REFRESH_TTL_SECONDS);
        this.audit = options.audit;
        this.risk = options.risk;
        this.keyPrefix = options.keyPrefix
            ? (0, keyNamespace_1.validateRedisKeyPrefix)(options.keyPrefix)
            : "";
        this.lock = new lockHelper_1.RedisLock(options.redisClient);
        this.sessionStore = new sessionStore_1.SessionStore(options.redisClient, this.scoped("sessions"));
        this.refreshKeys = new jwk_1.JwtKeyRing({
            legacySecret: options.refreshTokenSecret,
            issuer: options.issuer,
            audience: options.audience,
        });
    }
    async generateRefreshToken(payload) {
        const userId = validateRefreshIdentifier(payload.userId, "generateRefreshToken: payload.userId");
        if (typeof payload.email !== "string" ||
            payload.email.length === 0 ||
            payload.email.length > 254 ||
            (0, safeString_1.containsControlCharacter)(payload.email)) {
            throw new Error("generateRefreshToken: payload.email is invalid");
        }
        const sessionId = payload.sessionId === undefined
            ? (0, crypto_1.randomUUID)()
            : validateRefreshIdentifier(payload.sessionId, "generateRefreshToken: payload.sessionId");
        const tokenPayload = {
            userId,
            email: payload.email,
            sessionId,
        };
        const token = await this.signRefreshToken(tokenPayload);
        const key = this.refreshKey(tokenPayload.userId, tokenPayload.sessionId);
        if (this.tokenStore.set) {
            await this.tokenStore.set(key, (0, tokenFingerprint_1.tokenFingerprint)(token), this.refreshTokenTtlSeconds());
            try {
                await this.trackRefreshFamily(tokenPayload.userId, tokenPayload.sessionId);
            }
            catch (error) {
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
        }
        catch (error) {
            await this.revokeRefreshFamily(tokenPayload.userId, tokenPayload.sessionId);
            throw error;
        }
        return token;
    }
    async refresh(refreshToken) {
        if (!refreshToken)
            throw new MissingTokenError();
        const decoded = await this.verifyRefreshToken(refreshToken);
        if (await this.risk?.isQuarantined(this.principal(decoded.userId, decoded.sessionId))) {
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
                }
                finally {
                    await this.revokeRefreshFamily(decoded.userId, decoded.sessionId);
                }
                throw new InvalidTokenError();
            }
            const newRefreshToken = await this.rotateTokenIfEnabled(key, storedToken, decoded);
            let newAccessToken;
            try {
                newAccessToken = await this.accessTokenSigner(decoded);
                await this.audit?.emit({
                    type: "refresh_token.rotated",
                    severity: "info",
                    outcome: "success",
                    actor: { type: "user", id: decoded.userId },
                    sessionId: decoded.sessionId,
                });
            }
            catch (error) {
                await this.revokeRefreshFamily(decoded.userId, decoded.sessionId);
                throw error;
            }
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
    async revokeAllSessions(userId, fallbackSessionIds = []) {
        const validUserId = validateRefreshIdentifier(userId, "userId");
        if (fallbackSessionIds.length > MAX_FALLBACK_SESSION_IDS) {
            throw new Error(`fallbackSessionIds must not contain more than ${MAX_FALLBACK_SESSION_IDS} entries`);
        }
        const validFallbackSessionIds = fallbackSessionIds.map((sessionId) => validateRefreshIdentifier(sessionId, "sessionId"));
        const indexedFamilies = this.redisClient?.hgetall
            ? await this.redisClient.hgetall(this.refreshFamilyIndexKey(validUserId))
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
            for (let offset = 0; offset < pendingSessionIds.length; offset += REFRESH_REVOCATION_BATCH_SIZE) {
                await Promise.all(pendingSessionIds
                    .slice(offset, offset + REFRESH_REVOCATION_BATCH_SIZE)
                    .map((sessionId) => this.tokenStore.del(this.refreshKey(validUserId, sessionId))));
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
    async rotateTokenIfEnabled(key, storedToken, decoded) {
        if (!this.rotateRefreshTokens)
            return undefined;
        if (!this.tokenStore.compareAndSet) {
            throw new Error("TokenStore must implement compareAndSet for atomic refresh rotation");
        }
        const newRefreshToken = await this.signRefreshToken(decoded);
        const rotated = await this.tokenStore.compareAndSet(key, storedToken, (0, tokenFingerprint_1.tokenFingerprint)(newRefreshToken), this.refreshTokenTtlSeconds());
        if (!rotated) {
            try {
                await this.reportConcurrentRefresh(decoded);
            }
            finally {
                await this.revokeRefreshFamily(decoded.userId, decoded.sessionId);
            }
            throw new InvalidTokenError("Concurrent refresh detected");
        }
        return newRefreshToken;
    }
    async verifyRefreshToken(refreshToken) {
        try {
            const decoded = await this.refreshKeys.verify(refreshToken, "refresh");
            const userId = validateRefreshIdentifier(decoded.userId, "userId");
            const sessionId = validateRefreshIdentifier(decoded.sessionId, "sessionId");
            if (typeof decoded.email !== "string" ||
                decoded.email.length === 0 ||
                decoded.email.length > 254 ||
                (0, safeString_1.containsControlCharacter)(decoded.email)) {
                throw new InvalidTokenError();
            }
            return {
                userId,
                email: decoded.email,
                sessionId,
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
            expiresInSeconds: this.refreshTokenTtl,
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
        return this.refreshTokenTtl;
    }
    refreshKey(userId, sessionId) {
        return this.scoped("refresh", pairDigest(userId, sessionId));
    }
    refreshFamilyIndexKey(userId) {
        return this.scoped("refresh-families", userId);
    }
    lockKey(userId, sessionId) {
        return this.scoped("lock", pairDigest(userId, sessionId));
    }
    scoped(...parts) {
        return [this.keyPrefix, ...parts].filter(Boolean).join(":");
    }
    principal(userId, sessionId) {
        return { kind: "human", id: userId, sessionId };
    }
    async reportConcurrentRefresh(decoded) {
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
exports.RefreshService = RefreshService;
//# sourceMappingURL=refreshService.js.map