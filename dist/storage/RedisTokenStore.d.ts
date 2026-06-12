export declare class RedisTokenStore {
    private redis?;
    private prefix;
    constructor(redis?: any | undefined, _debug?: boolean);
    private key;
    storeRefreshToken(token: string, userId: string, ttl: number): Promise<void>;
    getRefreshToken(userId: string): Promise<any>;
    getset(key: string, value: string, expiry?: number): Promise<string | null>;
    deleteRefreshToken(userId: string): Promise<void>;
    blacklistToken(userId: string, ttl: number): Promise<void>;
    isBlacklisted(userId: string): Promise<boolean>;
    incrementRateLimit(ip: string, ttl: number): Promise<any>;
    addToWhitelist(ip: string): Promise<void>;
    removeFromWhitelist(ip: string): Promise<void>;
    isWhitelisted(ip: string): Promise<boolean>;
    set(key: string, value: string, expiry?: number): Promise<void>;
    get(key: string): Promise<string | null>;
}
//# sourceMappingURL=RedisTokenStore.d.ts.map