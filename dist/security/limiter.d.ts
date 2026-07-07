import { Redis as RedisClient } from "ioredis";
import { Request, Response, NextFunction } from "express";
type TokenBucketResult = {
    allowed: boolean;
    remaining: number;
    retryAfter?: number;
};
export declare class TokenBucket {
    private readonly redis;
    constructor(redis: RedisClient);
    consume(key: string, capacity: number, refillRate: number): Promise<TokenBucketResult>;
}
export declare const initializeRateLimiter: () => Promise<TokenBucket>;
export declare const createRatelimiter: (config: {
    capacity: number;
    refillRate: number;
    keyGenerator: (req: Request) => string;
}) => (req: Request, res: Response, next: NextFunction) => Promise<void>;
export declare const OTPLimiterMiddleware: (req: Request, res: Response, next: NextFunction) => Promise<void>;
export declare const LoginLimiterMiddleware: () => (req: Request, res: Response, next: NextFunction) => Promise<void>;
export {};
//# sourceMappingURL=limiter.d.ts.map