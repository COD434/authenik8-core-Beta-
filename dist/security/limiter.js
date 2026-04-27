"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.LoginLimiterMiddleware = exports.OTPLimiterMiddleware = exports.createRatelimiter = exports.initializeRateLimiter = exports.TokenBucket = void 0;
const dotenv_1 = __importDefault(require("dotenv"));
const redisService_1 = require("../redis/redisService");
dotenv_1.default.config();
class TokenBucket {
    constructor(redisClient) {
        this.redis = redisClient;
    }
    async consume(key, capacity, refillRate) {
        const now = Date.now();
        const results = await this.redis
            .pipeline()
            .hgetall(`rate_limit:${key}`)
            .exec();
        const data = results?.[0]?.[1] ?? {};
        const bucket = data
            || {};
        const currentToken = parseFloat(bucket.tokens || capacity.toString());
        const lastRefill = parseFloat(bucket.lastRefill || now.toString());
        const timeElapsed = (now - lastRefill) / 1000;
        const newToken = Math.min(capacity, currentToken + (timeElapsed * refillRate));
        if (newToken < 1) {
            return {
                allowed: false,
                remaining: Math.floor(newToken),
                retryAfter: Math.ceil((1 - newToken) / refillRate)
            };
        }
        await this.redis.hset(`rate_limit:${key}`, {
            tokens: (newToken - 1).toString(),
            lastRefill: now.toString()
        });
        this.redis.expire(`rate_limit:${key}`, 3600);
        return { allowed: true, remaining: Math.floor(newToken - 1) };
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
        catch (error) {
            console.error("Rate limiter unavailable:", error);
            res.status(503).json({
                error: "Rate limiter unavailable"
            });
            return;
        }
        const { allowed, remaining, retryAfter } = await bucket.consume(key, config.capacity, config.refillRate);
        res.set({
            "X-RateLimit-Limit": config.capacity.toString(),
            "X-RateLimit-Remaining": remaining.toString(),
            ...(!allowed && { "Retry-After": retryAfter?.toString() || "1" })
        });
        if (allowed) {
            return next();
        }
        else {
            res.status(429).json({
                error: `Too many requests`
            });
        }
    };
};
exports.createRatelimiter = createRatelimiter;
const RATE_LIMIT_CONFIGS = {
    OTP: {
        keyPrefix: "otp_limiter",
        refillRate: 0.1,
        capacity: 3,
        keyGenerator: (req) => {
            const email = req.body?.email;
            return email || req.ip || "unknown";
        }
    },
    LOGIN: {
        keyPrefix: "login_limiter",
        capacity: 10,
        refillRate: 2,
        keyGenerator: (req) => req.ip || "unknown"
    }
};
exports.OTPLimiterMiddleware = (0, exports.createRatelimiter)(RATE_LIMIT_CONFIGS.OTP);
const LoginLimiterMiddleware = () => (0, exports.createRatelimiter)(RATE_LIMIT_CONFIGS.LOGIN);
exports.LoginLimiterMiddleware = LoginLimiterMiddleware;
//# sourceMappingURL=limiter.js.map