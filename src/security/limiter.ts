import dotenv from "dotenv";
import { Redis as RedisClient } from "ioredis";
import { setupRedis } from "../redis/redisService";
import { Request, Response, NextFunction } from "express";
dotenv.config();

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

type TokenBucketResult = {
  allowed: boolean;
  remaining: number;
  retryAfter?: number;
};

export class TokenBucket {
  constructor(private readonly redis: RedisClient) {}

  async consume(
    key: string,
    capacity: number,
    refillRate: number
  ): Promise<TokenBucketResult> {
    if (capacity <= 0 || refillRate <= 0) {
      throw new Error("TokenBucket capacity and refillRate must be greater than zero");
    }

    const result = (await this.redis.eval(
      TOKEN_BUCKET_SCRIPT,
      1,
      `rate_limit:${key}`,
      capacity.toString(),
      refillRate.toString(),
      Date.now().toString(),
      "3600"
    )) as Array<number | string>;

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

let tokenBucket: TokenBucket;
let tokenBucketPromise: Promise<TokenBucket> | null = null;

export const initializeRateLimiter = async () => {
  const redisClient = (await setupRedis()).redisClient;
  tokenBucket = new TokenBucket(redisClient);
  return tokenBucket;
};

const getTokenBucket = async () => {
  if (tokenBucket) {
    return tokenBucket;
  }

  if (!tokenBucketPromise) {
    tokenBucketPromise = initializeRateLimiter().catch((error) => {
      tokenBucketPromise = null;
      throw error;
    });
  }

  return tokenBucketPromise;
};

export const createRatelimiter = (config: {
  capacity: number;
  refillRate: number;
  keyGenerator: (req: Request) => string;
}) => {
  return async (
    req: Request,
    res: Response,
    next: NextFunction
  ): Promise<void> => {
    const key = config.keyGenerator(req);
    let bucket: TokenBucket;

    try {
      bucket = await getTokenBucket();
    } catch {
      res.status(503).json({ error: "Rate limiter unavailable" });
      return;
    }

    const { allowed, remaining, retryAfter } = await bucket.consume(
      key,
      config.capacity,
      config.refillRate
    );

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

const RATE_LIMIT_CONFIGS = {
  OTP: {
    refillRate: 0.1,
    capacity: 3,
    keyGenerator: (req: Request) => req.body?.email || req.ip || "unknown",
  },

  LOGIN: {
    capacity: 10,
    refillRate: 2,
    keyGenerator: (req: Request): string => req.ip || "unknown",
  },
};

export const OTPLimiterMiddleware = createRatelimiter(RATE_LIMIT_CONFIGS.OTP);
export const LoginLimiterMiddleware = () =>
  createRatelimiter(RATE_LIMIT_CONFIGS.LOGIN);
