"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.LoginLimiterMiddleware = exports.OTPLimiterMiddleware = exports.createRatelimiter = exports.initializeRateLimiter = exports.TokenBucket = void 0;
const dotenv_1 = __importDefault(require("dotenv"));
const redisService_1 = require("../redis/redisService");
dotenv_1.default.config();
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
  return {0, math.floor(available), retryAfter}
end

available = available - 1
redis.call("HSET", key, "tokens", tostring(available), "lastRefill", tostring(now))
redis.call("EXPIRE", key, ttl)
return {1, math.floor(available), 0}
`;
class TokenBucket {
    constructor(redis) {
        this.redis = redis;
    }
    async consume(key, capacity, refillRate) {
        if (capacity <= 0 || refillRate <= 0) {
            throw new Error("TokenBucket capacity and refillRate must be greater than zero");
        }
        const result = (await this.redis.eval(TOKEN_BUCKET_SCRIPT, 1, `rate_limit:${key}`, capacity.toString(), refillRate.toString(), Date.now().toString(), "3600"));
        const allowed = Number(result[0]) === 1;
        const remaining = Number(result[1] ?? 0);
        const retryAfter = Number(result[2] ?? 0);
        return {
            allowed,
            remaining,
            ...(allowed ? {} : { retryAfter }),
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
    if (tokenBucket) {
        return tokenBucket;
    }
    if (!tokenBucketPromise) {
        tokenBucketPromise = (0, exports.initializeRateLimiter)().catch((error) => {
            tokenBucketPromise = null;
            throw error;
        });
    }
    return tokenBucketPromise;
};
const createRatelimiter = (config) => {
    return async (req, res, next) => {
        const key = config.keyGenerator(req);
        let bucket;
        try {
            bucket = await getTokenBucket();
        }
        catch {
            res.status(503).json({ error: "Rate limiter unavailable" });
            return;
        }
        const { allowed, remaining, retryAfter } = await bucket.consume(key, config.capacity, config.refillRate);
        res.set({
            "X-RateLimit-Limit": config.capacity.toString(),
            "X-RateLimit-Remaining": remaining.toString(),
            ...(!allowed && { "Retry-After": retryAfter?.toString() || "1" }),
        });
        if (allowed) {
            return next();
        }
        res.status(429).json({ error: "Too many requests" });
    };
};
exports.createRatelimiter = createRatelimiter;
const RATE_LIMIT_CONFIGS = {
    OTP: {
        refillRate: 0.1,
        capacity: 3,
        keyGenerator: (req) => req.body?.email || req.ip || "unknown",
    },
    LOGIN: {
        capacity: 10,
        refillRate: 2,
        keyGenerator: (req) => req.ip || "unknown",
    },
};
exports.OTPLimiterMiddleware = (0, exports.createRatelimiter)(RATE_LIMIT_CONFIGS.OTP);
const LoginLimiterMiddleware = () => (0, exports.createRatelimiter)(RATE_LIMIT_CONFIGS.LOGIN);
exports.LoginLimiterMiddleware = LoginLimiterMiddleware;
//# sourceMappingURL=limiter.js.map