import { createHash } from "crypto";
import type { NextFunction, Request, Response } from "express";
import { Redis as RedisClient } from "ioredis";
import { validateRedisKeyPrefix } from "../redis/keyNamespace";
import { setupRedis } from "../redis/redisService";
import { getClientIp } from "./requestContext";

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

type TokenBucketResult = {
  allowed: boolean;
  remaining: number;
  retryAfter?: number;
};

const validateLimit = (value: number, name: string): void => {
  if (!Number.isFinite(value) || value <= 0 || value > 1_000_000) {
    throw new Error(`${name} must be greater than zero and at most 1000000`);
  }
};

export class TokenBucket {
  private readonly keyPrefix: string;

  constructor(
    private readonly redis: RedisClient,
    keyPrefix = "authenik8:limiter",
  ) {
    this.keyPrefix = validateRedisKeyPrefix(keyPrefix);
  }

  async consume(
    key: string,
    capacity: number,
    refillRate: number,
  ): Promise<TokenBucketResult> {
    validateLimit(capacity, "TokenBucket capacity");
    validateLimit(refillRate, "TokenBucket refillRate");
    const keyDigest = createHash("sha256")
      .update(key.slice(0, 2048))
      .digest("base64url");
    const ttl = Math.max(
      60,
      Math.min(86_400, Math.ceil((capacity / refillRate) * 2)),
    );

    const result = (await this.redis.eval(
      TOKEN_BUCKET_SCRIPT,
      1,
      `${this.keyPrefix}:bucket:${keyDigest}`,
      capacity.toString(),
      refillRate.toString(),
      Date.now().toString(),
      ttl.toString(),
    )) as unknown;
    if (
      !Array.isArray(result) ||
      result.length < 3 ||
      !result.every(
        (value) => typeof value === "number" || typeof value === "string",
      )
    ) {
      throw new Error("TokenBucket Redis script returned an invalid result");
    }

    const allowed = Number(result[0]) === 1;
    const remaining = Number(result[1]);
    const retryAfter = Number(result[2]);
    if (
      !Number.isFinite(remaining) ||
      !Number.isFinite(retryAfter) ||
      retryAfter < 0
    ) {
      throw new Error("TokenBucket Redis result contains invalid values");
    }

    return {
      allowed,
      remaining: Math.max(0, remaining),
      ...(allowed ? {} : { retryAfter: Math.max(1, retryAfter) }),
    };
  }
}

let tokenBucket: TokenBucket | undefined;
let tokenBucketPromise: Promise<TokenBucket> | null = null;

export const initializeRateLimiter = async (): Promise<TokenBucket> => {
  const redisClient = (await setupRedis()).redisClient;
  tokenBucket = new TokenBucket(redisClient);
  return tokenBucket;
};

const getTokenBucket = async (): Promise<TokenBucket> => {
  if (tokenBucket) return tokenBucket;
  if (!tokenBucketPromise) {
    tokenBucketPromise = initializeRateLimiter().catch((error) => {
      tokenBucketPromise = null;
      throw error;
    });
  }
  return tokenBucketPromise;
};

type RateLimiterConfig = {
  capacity: number;
  refillRate: number;
  keyGenerator: (req: Request) => string | readonly string[];
};

export const createRatelimiter = (config: RateLimiterConfig) => {
  validateLimit(config.capacity, "Rate limiter capacity");
  validateLimit(config.refillRate, "Rate limiter refillRate");

  return async (
    req: Request,
    res: Response,
    next: NextFunction,
  ): Promise<void> => {
    const generated = config.keyGenerator(req);
    const keys = (Array.isArray(generated) ? generated : [generated])
      .filter((key): key is string => typeof key === "string" && key.length > 0)
      .slice(0, 4);
    if (keys.length === 0) keys.push("unknown");

    let bucket: TokenBucket;
    try {
      bucket = await getTokenBucket();
      const results = await Promise.all(
        keys.map((key) =>
          bucket.consume(key, config.capacity, config.refillRate),
        ),
      );
      const denied = results.find((result) => !result.allowed);
      const remaining = Math.min(
        ...results.map((result) => result.remaining),
      );

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
    } catch {
      res.status(503).json({ error: "Rate limiter unavailable" });
    }
  };
};

const boundedEmail = (request: Request): string => {
  const email = request.body?.email;
  if (typeof email !== "string") return "invalid-email";
  const normalized = email.trim().toLowerCase();
  return normalized.length > 0 && normalized.length <= 254
    ? normalized
    : "invalid-email";
};

const RATE_LIMIT_CONFIGS = {
  OTP: {
    refillRate: 0.1,
    capacity: 3,
    keyGenerator: (req: Request) => [
      `otp:email:${boundedEmail(req)}`,
      `otp:ip:${getClientIp(req)}`,
    ],
  },
  LOGIN: {
    capacity: 10,
    refillRate: 2,
    keyGenerator: (req: Request): string => `login:ip:${getClientIp(req)}`,
  },
};

export const OTPLimiterMiddleware = createRatelimiter(RATE_LIMIT_CONFIGS.OTP);
export const LoginLimiterMiddleware = () =>
  createRatelimiter(RATE_LIMIT_CONFIGS.LOGIN);
