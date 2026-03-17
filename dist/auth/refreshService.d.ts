export declare class MissingTokenError extends Error {
    constructor(message?: string);
}
export declare class InvalidTokenError extends Error {
    constructor(message?: string);
}
export interface TokenStore {
    get(key: string): Promise<string | null>;
    set?(key: string, value: string, expiry?: number): Promise<void>;
    del?(key: string): Promise<void>;
}
export interface RefreshServiceOptions {
    redisClient: TokenStore;
    accessTokenSecret: string;
    refreshTokenSecret: string;
    accessTokenExpiry: string;
    rotateRefreshTokens?: boolean;
    refreshTokenExpiry?: string;
}
export interface RefreshResult {
    accessToken: string;
    refreshToken?: string;
}
export declare class RefreshService {
    private redisClient;
    private accessTokenSecret;
    private refreshTokenSecret;
    private accessTokenExpiry;
    private rotateRefreshTokens;
    private refreshTokenExpiry;
    constructor(options: RefreshServiceOptions);
    refresh(refreshToken?: string): Promise<RefreshResult>;
}
//# sourceMappingURL=refreshService.d.ts.map