import type { NextFunction, Request, Response } from "express";
import type { Authenik8JwkConfig } from "./jwk";
import { SessionMetadata } from "./sessionStore";
export interface JwtPayload {
    [key: string]: unknown;
    userId?: string;
    email?: string;
    role?: string;
    sessionId?: string;
    type?: string;
    id?: string;
    createdAt?: number;
    tokenUse?: string;
    exp?: number;
    iat?: number;
    iss?: string;
    aud?: string | string[];
    jti?: string;
}
export interface JWTOptions {
    jwtSecret?: string;
    jwk?: Authenik8JwkConfig;
    issuer?: string;
    audience?: string | string[];
    expiry?: string | number;
    redisClient?: any;
    onGuestToken?: () => void;
    allowCookieAuth?: boolean;
}
type SignablePayload = Record<string, unknown> & {
    userId?: string;
    sessionId?: string;
};
export declare class JWTService {
    private readonly expiry;
    private readonly redisClient?;
    private readonly onGuestToken?;
    private readonly allowCookieAuth;
    private readonly sessionStore;
    private readonly keyRing;
    constructor(options: JWTOptions);
    get issuer(): string;
    get audience(): string | string[];
    getJwks(): import("jose", { with: { "resolution-mode": "import" } }).JSONWebKeySet;
    listSessions(userId: string): Promise<SessionMetadata[]>;
    revokeAllSessions(userId: string): Promise<void>;
    revokeSession(userId: string, sessionId: string): Promise<void>;
    signToken(payload: SignablePayload, meta?: {
        device?: string;
        ip?: string;
    }): Promise<string>;
    guestToken(): Promise<string>;
    verifyToken(token: string): Promise<JwtPayload | null>;
    verifyActiveToken(token: string): Promise<JwtPayload | null>;
    hasActiveSession(userId: string, sessionId: string): Promise<boolean>;
    verifyGuestToken(token: string): Promise<JwtPayload | null>;
    authenticateJWT: (req: Request, res: Response, next: NextFunction) => Promise<void | Response<any, Record<string, any>>>;
    private tokenFromRequest;
    private sessionIsValid;
    private persistSessionToken;
}
export {};
//# sourceMappingURL=jwtAuth.d.ts.map