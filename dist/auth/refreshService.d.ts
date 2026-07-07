import { SignOptions } from "jsonwebtoken";
export declare class MissingTokenError extends Error {
    constructor(message?: string);
}
export declare class InvalidTokenError extends Error {
    constructor(message?: string);
}
interface RefreshTokenPayload {
    userId: string;
    email: string;
    sessionId?: string;
}
export interface TokenStore {
    get(key: string): Promise<string | null>;
    set?(key: string, value: string, expiry?: number): Promise<void>;
    del?(key: string): Promise<void>;
    compareAndSet?(key: string, expected: string, value: string, expiry?: number): Promise<boolean>;
}
export interface RefreshServiceOptions {
    tokenStore: TokenStore;
    accessTokenSecret: string;
    redisClient: any;
    refreshTokenSecret: string;
    accessTokenExpiry: SignOptions["expiresIn"];
    rotateRefreshTokens?: boolean;
    refreshTokenExpiry?: string | number;
}
export interface RefreshResult {
    accessToken: string;
    refreshToken?: string;
}
export declare class RefreshService {
    private readonly tokenStore;
    private readonly accessTokenSecret;
    private readonly refreshTokenSecret;
    private readonly accessTokenExpiry;
    private readonly rotateRefreshTokens;
    private readonly refreshTokenExpiry;
    private readonly lock;
    private readonly sessionStore;
    constructor(options: RefreshServiceOptions);
    generateRefreshToken(payload: RefreshTokenPayload): Promise<string>;
    refresh(refreshToken?: string): Promise<RefreshResult>;
    private rotateTokenIfEnabled;
    private verifyRefreshToken;
    private signRefreshToken;
    private signAccessToken;
    private persistSessionToken;
    private revokeRefreshFamily;
    private refreshTokenTtlSeconds;
    private refreshKey;
    private lockKey;
}
export {};
//# sourceMappingURL=refreshService.d.ts.map