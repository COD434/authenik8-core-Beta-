"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.SessionStore = void 0;
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
    constructor(redis, namespace = "sessions") {
        this.redis = redis;
        this.namespace = namespace;
    }
    sessionKey(principalId) {
        return `${this.namespace}:${principalId}`;
    }
    async list(principalId) {
        if (!this.redis?.hgetall)
            return [];
        const sessions = await this.redis.hgetall(this.sessionKey(principalId));
        return Object.values(sessions || {})
            .map(parseSession)
            .filter((session) => !!session)
            .map(metadataFromSession);
    }
    async get(principalId, sessionId) {
        if (!this.redis)
            return null;
        if (this.redis.hget) {
            return parseSession(await this.redis.hget(this.sessionKey(principalId), sessionId));
        }
        if (!this.redis.hgetall)
            return null;
        const sessions = await this.redis.hgetall(this.sessionKey(principalId));
        return parseSession(sessions?.[sessionId]);
    }
    async upsert(principalId, token, metadata, ttlSeconds) {
        if (!this.redis?.hset)
            return;
        await this.redis.hset(this.sessionKey(principalId), metadata.sessionId, JSON.stringify({ token, ...metadata }));
        if (this.redis.expire) {
            await this.redis.expire(this.sessionKey(principalId), ttlSeconds);
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
        return session?.token === token;
    }
    async revoke(principalId, sessionId) {
        if (!this.redis?.hdel)
            return;
        await this.redis.hdel(this.sessionKey(principalId), sessionId);
    }
    async revokeAll(principalId) {
        if (!this.redis?.del)
            return;
        await this.redis.del(this.sessionKey(principalId));
    }
}
exports.SessionStore = SessionStore;
//# sourceMappingURL=sessionStore.js.map