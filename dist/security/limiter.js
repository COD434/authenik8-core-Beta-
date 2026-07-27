"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.LoginLimiterMiddleware = exports.OTPLimiterMiddleware = exports.createRatelimiter = exports.initializeRateLimiter = exports.TokenBucket = void 0;
const crypto_1 = require("crypto");
const keyNamespace_1 = require("../redis/keyNamespace");
const redisService_1 = require("../redis/redisService");
const requestContext_1 = require("./requestContext");
const TOKEN_BUCKET_SCRIPT = `
local key = KEYS[1]
local capacity = tonumber(ARGV[1])
local refillRate = tonumber(ARGV[2])
local now = tonumber(ARGV[3])
local ttl = tonumber(ARGV[4])

local bucket = redis.call("HMGET", key, "tokens", "lastRefill")
local tokens = tonumber(bucket[1]) or capacity
local lastRefill = tonumber(bucket[2]) or now
local elapsed = math.max(0, (now - lastRefill) / 1000)
local available = math.min(capacity, tokens + (elapsed * refillRate))

if available < 1 then
  local retryAfter = math.ceil((1 - available) / refillRate)
  redis.call("HSET", key, "tokens", tostring(available), "lastRefill", tostring(now))
  redis.call("EXPIRE", key, ttl)
  return {0, math.floor(available), retryAfter}
end

available = available - 1
redis.call("HSET", key, "tokens", tostring(available), "lastRefill", tostring(now))
redis.call("EXPIRE", key, ttl)
return {1, math.floor(available), 0}
`;
const validateLimit = (value, name) => {
    if (!Number.isFinite(value) || value <= 0 || value > 1000000) {
        throw new Error(`${name} must be greater than zero and at most 1000000`);
    }
};
class TokenBucket {
    constructor(redis, keyPrefix = "authenik8:limiter") {
        this.redis = redis;
        this.keyPrefix = (0, keyNamespace_1.validateRedisKeyPrefix)(keyPrefix);
    }
    async consume(key, capacity, refillRate) {
        validateLimit(capacity, "TokenBucket capacity");
        validateLimit(refillRate, "TokenBucket refillRate");
        const keyDigest = (0, crypto_1.createHash)("sha256")
            .update(key.slice(0, 2048))
            .digest("base64url");
        const ttl = Math.max(60, Math.min(86400, Math.ceil((capacity / refillRate) * 2)));
        const result = (await this.redis.eval(TOKEN_BUCKET_SCRIPT, 1, `${this.keyPrefix}:bucket:${keyDigest}`, capacity.toString(), refillRate.toString(), Date.now().toString(), ttl.toString()));
        if (!Array.isArray(result) ||
            result.length < 3 ||
            !result.every((value) => typeof value === "number" || typeof value === "string")) {
            throw new Error("TokenBucket Redis script returned an invalid result");
        }
        const allowed = Number(result[0]) === 1;
        const remaining = Number(result[1]);
        const retryAfter = Number(result[2]);
        if (!Number.isFinite(remaining) ||
            !Number.isFinite(retryAfter) ||
            retryAfter < 0) {
            throw new Error("TokenBucket Redis result contains invalid values");
        }
        return {
            allowed,
            remaining: Math.max(0, remaining),
            ...(allowed ? {} : { retryAfter: Math.max(1, retryAfter) }),
        };
    }
}
exports.TokenBucket = TokenBucket;
let tokenBucket;
let tokenBucketPromise = null;
const initializeRateLimiter = async () => {
    const redisClient = (await (0, redisService_1.setupRedis)()).redisClient;
    tokenBucket = new TokenBucket(redisClient);
    return tokenBucket;
};
exports.initializeRateLimiter = initializeRateLimiter;
const getTokenBucket = async () => {
    if (tokenBucket)
        return tokenBucket;
    if (!tokenBucketPromise) {
        tokenBucketPromise = (0, exports.initializeRateLimiter)().catch((error) => {
            tokenBucketPromise = null;
            throw error;
        });
    }
    return tokenBucketPromise;
};
const createRatelimiter = (config) => {
    validateLimit(config.capacity, "Rate limiter capacity");
    validateLimit(config.refillRate, "Rate limiter refillRate");
    return async (req, res, next) => {
        const generated = config.keyGenerator(req);
        const keys = (Array.isArray(generated) ? generated : [generated])
            .filter((key) => typeof key === "string" && key.length > 0)
            .slice(0, 4);
        if (keys.length === 0)
            keys.push("unknown");
        let bucket;
        try {
            bucket = await getTokenBucket();
            const results = await Promise.all(keys.map((key) => bucket.consume(key, config.capacity, config.refillRate)));
            const denied = results.find((result) => !result.allowed);
            const remaining = Math.min(...results.map((result) => result.remaining));
            res.set({
                "X-RateLimit-Limit": config.capacity.toString(),
                "X-RateLimit-Remaining": remaining.toString(),
                ...(denied
                    ? { "Retry-After": (denied.retryAfter ?? 1).toString() }
                    : {}),
            });
            if (!denied) {
                next();
                return;
            }
            res.status(429).json({ error: "Too many requests" });
        }
        catch {
            res.status(503).json({ error: "Rate limiter unavailable" });
        }
    };
};
exports.createRatelimiter = createRatelimiter;
const boundedEmail = (request) => {
    const email = request.body?.email;
    if (typeof email !== "string")
        return "invalid-email";
    const normalized = email.trim().toLowerCase();
    return normalized.length > 0 && normalized.length <= 254
        ? normalized
        : "invalid-email";
};
const RATE_LIMIT_CONFIGS = {
    OTP: {
        refillRate: 0.1,
        capacity: 3,
        keyGenerator: (req) => [
            `otp:email:${boundedEmail(req)}`,
            `otp:ip:${(0, requestContext_1.getClientIp)(req)}`,
        ],
    },
    LOGIN: {
        capacity: 10,
        refillRate: 2,
        keyGenerator: (req) => `login:ip:${(0, requestContext_1.getClientIp)(req)}`,
    },
};
exports.OTPLimiterMiddleware = (0, exports.createRatelimiter)(RATE_LIMIT_CONFIGS.OTP);
const LoginLimiterMiddleware = () => (0, exports.createRatelimiter)(RATE_LIMIT_CONFIGS.LOGIN);
exports.LoginLimiterMiddleware = LoginLimiterMiddleware;
//# sourceMappingURL=limiter.js.map