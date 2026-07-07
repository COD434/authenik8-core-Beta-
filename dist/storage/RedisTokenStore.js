"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.RedisTokenStore = void 0;
const COMPARE_AND_SET_SCRIPT = `
if redis.call("GET", KEYS[1]) == ARGV[1] then
  if ARGV[3] ~= "" then
    redis.call("SET", KEYS[1], ARGV[2], "EX", tonumber(ARGV[3]))
  else
    redis.call("SET", KEYS[1], ARGV[2])
  end
  return 1
end
return 0
`;
class RedisTokenStore {
    constructor(redis, _debug = false) {
        this.redis = redis;
        this.prefix = "auth:v1";
    }
    async storeRefreshToken(token, userId, ttl) {
        await this.redis.set(this.key("refresh", userId), token, "EX", ttl);
    }
    async getRefreshToken(userId) {
        return this.redis.get(this.key("refresh", userId));
    }
    async compareAndSet(key, expected, value, expiry) {
        const result = await this.redis.eval(COMPARE_AND_SET_SCRIPT, 1, key, expected, value, expiry ? expiry.toString() : "");
        return Number(result) === 1;
    }
    async deleteRefreshToken(userId) {
        await this.redis.del(this.key("refresh", userId));
    }
    async del(key) {
        await this.redis.del(key);
    }
    async blacklistToken(userId, ttl) {
        await this.redis.set(this.key("blacklist", userId), "1", "EX", ttl);
    }
    async isBlacklisted(userId) {
        const exists = await this.redis.exists(this.key("blacklist", userId));
        return exists === 1;
    }
    async incrementRateLimit(ip, ttl) {
        const key = this.key("rate", ip);
        const count = await this.redis.incr(key);
        if (count === 1) {
            await this.redis.expire(key, ttl);
        }
        return count;
    }
    async addToWhitelist(ip) {
        await this.redis.set(this.key("whitelist", ip), "1");
    }
    async removeFromWhitelist(ip) {
        await this.redis.del(this.key("whitelist", ip));
    }
    async isWhitelisted(ip) {
        const exists = await this.redis.exists(this.key("whitelist", ip));
        return exists === 1;
    }
    async set(key, value, expiry) {
        if (expiry) {
            await this.redis.set(key, value, "EX", expiry);
            return;
        }
        await this.redis.set(key, value);
    }
    async get(key) {
        return this.redis.get(key);
    }
    key(...parts) {
        return `${this.prefix}:${parts.join(":")}`;
    }
}
exports.RedisTokenStore = RedisTokenStore;
//# sourceMappingURL=RedisTokenStore.js.map