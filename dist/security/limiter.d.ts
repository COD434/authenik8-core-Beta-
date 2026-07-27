import type { NextFunction, Request, Response } from "express";
import { Redis as RedisClient } from "ioredis";
type TokenBucketResult = {
    allowed: boolean;
    remaining: number;
    retryAfter?: number;
};
export declare class TokenBucket {
    private readonly redis;
    private readonly keyPrefix;
    constructor(redis: RedisClient, keyPrefix?: string);
    consume(key: string, capacity: number, refillRate: number): Promise<TokenBucketResult>;
}
export declare const initializeRateLimiter: () => Promise<TokenBucket>;
type RateLimiterConfig = {
    capacity: number;
    refillRate: number;
    keyGenerator: (req: Request) => string | readonly string[];
};
export declare const createRatelimiter: (config: RateLimiterConfig) => (req: Request, res: Response, next: NextFunction) => Promise<void>;
export declare const OTPLimiterMiddleware: (req: Request, res: Response, next: NextFunction) => Promise<void>;
export declare const LoginLimiterMiddleware: () => (req: Request, res: Response, next: NextFunction) => Promise<void>;
export {};
//# sourceMappingURL=limiter.d.ts.map