"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.SessionStore = void 0;
const sessionKey = (userId) => `sessions:${userId}`;
const parseSession = (value) => {
    if (!value)
        return null;
    try {
        const parsed = JSON.parse(value);
        if (!parsed.sessionId || !parsed.token)
            return null;
        return parsed;
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
class SessionStore {
    constructor(redis) {
        this.redis = redis;
    }
    async list(userId) {
        if (!this.redis?.hgetall)
            return [];
        const sessions = await this.redis.hgetall(sessionKey(userId));
        return Object.values(sessions || {})
            .map(parseSession)
            .filter((session) => !!session)
            .map(metadataFromSession);
    }
    async get(userId, sessionId) {
        if (!this.redis)
            return null;
        if (this.redis.hget) {
            return parseSession(await this.redis.hget(sessionKey(userId), sessionId));
        }
        if (!this.redis.hgetall)
            return null;
        const sessions = await this.redis.hgetall(sessionKey(userId));
        return parseSession(sessions?.[sessionId]);
    }
    async upsert(userId, token, metadata, ttlSeconds) {
        if (!this.redis?.hset)
            return;
        await this.redis.hset(sessionKey(userId), metadata.sessionId, JSON.stringify({ token, ...metadata }));
        if (this.redis.expire) {
            await this.redis.expire(sessionKey(userId), ttlSeconds);
        }
    }
    async updateToken(userId, sessionId, token, ttlSeconds, defaults) {
        const existing = await this.get(userId, sessionId);
        const metadata = existing
            ? metadataFromSession(existing)
            : {
                sessionId,
                device: defaults?.device ?? "unknown",
                ip: defaults?.ip ?? "unknown",
                createdAt: defaults?.createdAt ?? Date.now(),
            };
        await this.upsert(userId, token, metadata, ttlSeconds);
    }
    async tokenMatches(userId, sessionId, token) {
        const session = await this.get(userId, sessionId);
        return session?.token === token;
    }
    async revoke(userId, sessionId) {
        if (!this.redis?.hdel)
            return;
        await this.redis.hdel(sessionKey(userId), sessionId);
    }
    async revokeAll(userId) {
        if (!this.redis?.del)
            return;
        await this.redis.del(sessionKey(userId));
    }
}
exports.SessionStore = SessionStore;
//# sourceMappingURL=sessionStore.js.map