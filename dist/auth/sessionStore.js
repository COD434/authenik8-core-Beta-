"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.sessionTokenMatches = exports.SessionStore = void 0;
const tokenFingerprint_1 = require("./tokenFingerprint");
const keyNamespace_1 = require("../redis/keyNamespace");
const safeString_1 = require("../utility/safeString");
const MAX_IDENTIFIER_LENGTH = 256;
const MAX_DEVICE_LENGTH = 512;
const MAX_IP_LENGTH = 128;
const MAX_TOKEN_LENGTH = 16 * 1024;
const MAX_SESSION_TTL_SECONDS = 31 * 24 * 60 * 60;
const TOKEN_HASH_PATTERN = /^[A-Za-z0-9_-]{43}$/;
const assertIdentifier = (value, label) => {
    if (typeof value !== "string" ||
        value.length === 0 ||
        value.length > MAX_IDENTIFIER_LENGTH ||
        (0, safeString_1.containsControlCharacter)(value)) {
        throw new Error(`${label} must contain between 1 and 256 safe characters`);
    }
    return value;
};
const isStoredSession = (value) => {
    if (!value || typeof value !== "object")
        return false;
    const session = value;
    return (typeof session.sessionId === "string" &&
        session.sessionId.length > 0 &&
        session.sessionId.length <= MAX_IDENTIFIER_LENGTH &&
        !(0, safeString_1.containsControlCharacter)(session.sessionId) &&
        typeof session.device === "string" &&
        session.device.length <= MAX_DEVICE_LENGTH &&
        !(0, safeString_1.containsControlCharacter)(session.device) &&
        typeof session.ip === "string" &&
        session.ip.length <= MAX_IP_LENGTH &&
        !(0, safeString_1.containsControlCharacter)(session.ip) &&
        typeof session.createdAt === "number" &&
        Number.isSafeInteger(session.createdAt) &&
        session.createdAt > 0 &&
        ((typeof session.tokenHash === "string" &&
            TOKEN_HASH_PATTERN.test(session.tokenHash)) ||
            (typeof session.token === "string" &&
                session.token.length > 0 &&
                session.token.length <= MAX_TOKEN_LENGTH)));
};
const parseSession = (value) => {
    if (!value || value.length > MAX_TOKEN_LENGTH + 2048)
        return null;
    try {
        const parsed = JSON.parse(value);
        return isStoredSession(parsed) ? parsed : null;
    }
    catch {
        return null;
    }
};
const metadataFromSession = (session) => ({
    sessionId: session.sessionId,
    device: session.device,
    ip: session.ip,
    createdAt: session.createdAt,
});
const validateMetadata = (metadata) => {
    assertIdentifier(metadata.sessionId, "sessionId");
    if (typeof metadata.device !== "string" ||
        metadata.device.length > MAX_DEVICE_LENGTH ||
        (0, safeString_1.containsControlCharacter)(metadata.device)) {
        throw new Error(`session device must not exceed ${MAX_DEVICE_LENGTH} characters`);
    }
    if (typeof metadata.ip !== "string" ||
        metadata.ip.length > MAX_IP_LENGTH ||
        (0, safeString_1.containsControlCharacter)(metadata.ip)) {
        throw new Error(`session IP must not exceed ${MAX_IP_LENGTH} characters`);
    }
    if (!Number.isSafeInteger(metadata.createdAt) ||
        metadata.createdAt <= 0) {
        throw new Error("session createdAt must be a positive timestamp");
    }
};
class SessionStore {
    constructor(redis, namespace = "sessions") {
        this.redis = redis;
        this.namespace = (0, keyNamespace_1.validateRedisKeyPrefix)(namespace);
    }
    sessionKey(principalId) {
        return `${this.namespace}:${assertIdentifier(principalId, "principalId")}`;
    }
    sessionField(sessionId) {
        return assertIdentifier(sessionId, "sessionId");
    }
    async list(principalId) {
        if (!this.redis?.hgetall)
            return [];
        const sessions = await this.redis.hgetall(this.sessionKey(principalId));
        return Object.entries(sessions || {})
            .map(([field, value]) => {
            const session = parseSession(value);
            return session?.sessionId === field ? session : null;
        })
            .filter((session) => !!session)
            .map(metadataFromSession);
    }
    async get(principalId, sessionId) {
        if (!this.redis)
            return null;
        const key = this.sessionKey(principalId);
        const field = this.sessionField(sessionId);
        if (this.redis.hget) {
            const session = parseSession(await this.redis.hget(key, field));
            return session?.sessionId === field ? session : null;
        }
        if (!this.redis.hgetall)
            return null;
        const sessions = await this.redis.hgetall(key);
        const session = parseSession(sessions?.[field]);
        return session?.sessionId === field ? session : null;
    }
    async upsert(principalId, token, metadata, ttlSeconds) {
        if (!this.redis?.hset)
            return;
        if (typeof token !== "string" ||
            token.length === 0 ||
            token.length > MAX_TOKEN_LENGTH) {
            throw new Error("session token is invalid or too large");
        }
        validateMetadata(metadata);
        if (!Number.isSafeInteger(ttlSeconds) ||
            ttlSeconds < 1 ||
            ttlSeconds > MAX_SESSION_TTL_SECONDS) {
            throw new Error("session TTL must be between 1 second and 31 days");
        }
        const key = this.sessionKey(principalId);
        await this.redis.hset(key, this.sessionField(metadata.sessionId), JSON.stringify({ tokenHash: (0, tokenFingerprint_1.tokenFingerprint)(token), ...metadata }));
        if (this.redis.expire) {
            await this.redis.expire(key, ttlSeconds);
        }
    }
    async updateToken(principalId, sessionId, token, ttlSeconds, defaults) {
        const existing = await this.get(principalId, sessionId);
        const metadata = existing
            ? metadataFromSession(existing)
            : {
                sessionId,
                device: defaults?.device ?? "unknown",
                ip: defaults?.ip ?? "unknown",
                createdAt: defaults?.createdAt ?? Date.now(),
            };
        await this.upsert(principalId, token, metadata, ttlSeconds);
    }
    async tokenMatches(principalId, sessionId, token) {
        const session = await this.get(principalId, sessionId);
        return session ? (0, exports.sessionTokenMatches)(session, token) : false;
    }
    async revoke(principalId, sessionId) {
        if (!this.redis?.hdel)
            return;
        await this.redis.hdel(this.sessionKey(principalId), this.sessionField(sessionId));
    }
    async revokeAll(principalId) {
        if (!this.redis?.del)
            return;
        await this.redis.del(this.sessionKey(principalId));
    }
}
exports.SessionStore = SessionStore;
const sessionTokenMatches = (session, token) => {
    if (session.tokenHash) {
        return (0, tokenFingerprint_1.tokenFingerprintMatches)(session.tokenHash, token);
    }
    return session.token
        ? (0, tokenFingerprint_1.tokenFingerprintMatches)((0, tokenFingerprint_1.tokenFingerprint)(session.token), token)
        : false;
};
exports.sessionTokenMatches = sessionTokenMatches;
//# sourceMappingURL=sessionStore.js.map