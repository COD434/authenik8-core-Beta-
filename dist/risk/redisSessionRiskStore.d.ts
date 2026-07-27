import type { Redis } from "ioredis";
import type { SessionRiskStore } from "./types";
export declare class RedisSessionRiskStore implements SessionRiskStore {
    private readonly redis;
    constructor(redis: Redis);
    get(key: string): Promise<string | null>;
    set(key: string, value: string, ttlSeconds: number): Promise<void>;
    setIfAbsent(key: string, value: string, ttlSeconds: number): Promise<boolean>;
    increment(key: string): Promise<number>;
    expire(key: string, ttlSeconds: number): Promise<void>;
    delete(keys: readonly string[]): Promise<void>;
}
//# sourceMappingURL=redisSessionRiskStore.d.ts.map