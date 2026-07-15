export declare class MissingTokenError extends Error {
    constructor(message?: string);
}
export declare class InvalidTokenError extends Error {
    constructor(message?: string);
}
interface RefreshTokenPayload {
    [key: string]: unknown;
    userId: string;
    email: string;
    sessionId?: string;
    tokenUse?: string;
}
type RequiredRefreshPayload = Required<Pick<RefreshTokenPayload, "userId" | "email" | "sessionId">>;
export interface TokenStore {
    get(key: string): Promise<string | null>;
    set?(key: string, value: string, expiry?: number): Promise<void>;
    del?(key: string): Promise<void>;
    compareAndSet?(key: string, expected: string, value: string, expiry?: number): Promise<boolean>;
}
export interface RefreshServiceOptions {
    tokenStore: TokenStore;
    redisClient: any;
    refreshTokenSecret: string;
    accessTokenSigner: (payload: RequiredRefreshPayload) => Promise<string>;
    issuer: string;
    audience: string | string[];
    rotateRefreshTokens?: boolean;
    refreshTokenExpiry?: string | number;
}
export interface RefreshResult {
    accessToken: string;
    refreshToken?: string;
}
export declare class RefreshService {
    private readonly tokenStore;
    private readonly accessTokenSigner;
    private readonly rotateRefreshTokens;
    private readonly refreshTokenExpiry;
    private readonly lock;
    private readonly sessionStore;
    private readonly refreshKeys;
    private readonly redisClient;
    constructor(options: RefreshServiceOptions);
    generateRefreshToken(payload: RefreshTokenPayload): Promise<string>;
    refresh(refreshToken?: string): Promise<RefreshResult>;
    revokeSession(userId: string, sessionId: string): Promise<void>;
    revokeAllSessions(userId: string, fallbackSessionIds?: string[]): Promise<void>;
    private rotateTokenIfEnabled;
    private verifyRefreshToken;
    private signRefreshToken;
    private revokeRefreshFamily;
    private trackRefreshFamily;
    private refreshTokenTtlSeconds;
    private refreshKey;
    private refreshFamilyIndexKey;
    private lockKey;
}
export {};
//# sourceMappingURL=refreshService.d.ts.map