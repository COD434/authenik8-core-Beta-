export declare class RedisTokenStore {
    private redis?;
    private readonly prefix;
    constructor(redis?: any | undefined, _debug?: boolean);
    storeRefreshToken(token: string, userId: string, ttl: number): Promise<void>;
    getRefreshToken(userId: string): Promise<string | null>;
    compareAndSet(key: string, expected: string, value: string, expiry?: number): Promise<boolean>;
    deleteRefreshToken(userId: string): Promise<void>;
    del(key: string): Promise<void>;
    blacklistToken(userId: string, ttl: number): Promise<void>;
    isBlacklisted(userId: string): Promise<boolean>;
    incrementRateLimit(ip: string, ttl: number): Promise<number>;
    addToWhitelist(ip: string): Promise<void>;
    removeFromWhitelist(ip: string): Promise<void>;
    isWhitelisted(ip: string): Promise<boolean>;
    set(key: string, value: string, expiry?: number): Promise<void>;
    get(key: string): Promise<string | null>;
    private key;
}
//# sourceMappingURL=RedisTokenStore.d.ts.map