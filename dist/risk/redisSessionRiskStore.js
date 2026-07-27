"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.RedisSessionRiskStore = void 0;
class RedisSessionRiskStore {
    constructor(redis) {
        this.redis = redis;
    }
    get(key) {
        return this.redis.get(key);
    }
    async set(key, value, ttlSeconds) {
        await this.redis.set(key, value, "EX", ttlSeconds);
    }
    async setIfAbsent(key, value, ttlSeconds) {
        return ((await this.redis.set(key, value, "EX", ttlSeconds, "NX")) === "OK");
    }
    increment(key) {
        return this.redis.incr(key);
    }
    async expire(key, ttlSeconds) {
        await this.redis.expire(key, ttlSeconds);
    }
    async delete(keys) {
        if (keys.length)
            await this.redis.del(...keys);
    }
}
exports.RedisSessionRiskStore = RedisSessionRiskStore;
//# sourceMappingURL=redisSessionRiskStore.js.map