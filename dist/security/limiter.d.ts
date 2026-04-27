import { Redis as RedisClient } from "ioredis";
import { Request, Response, NextFunction } from "express";
export declare class TokenBucket {
    private redis;
    constructor(redisClient: RedisClient);
    consume(key: string, capacity: number, refillRate: number): Promise<{
        allowed: boolean;
        remaining: number;
        retryAfter?: number;
    }>;
}
export declare const initializeRateLimiter: () => Promise<TokenBucket>;
export declare const createRatelimiter: (config: {
    capacity: number;
    refillRate: number;
    keyGenerator: (req: Request) => string;
}) => (req: Request, res: Response, next: NextFunction) => Promise<void>;
export declare const OTPLimiterMiddleware: (req: Request, res: Response, next: NextFunction) => Promise<void>;
export declare const LoginLimiterMiddleware: () => (req: Request, res: Response, next: NextFunction) => Promise<void>;
//# sourceMappingURL=limiter.d.ts.map