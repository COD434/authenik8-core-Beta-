import type { NextFunction, Request, Response } from "express";
import type { Authenik8JwkConfig } from "./jwk";
import { SessionMetadata } from "./sessionStore";
import type { AuditEmitter } from "../audit/types";
import type { SessionObservation, SessionRiskReporter } from "../risk/types";
export interface JwtPayload {
    [key: string]: unknown;
    userId?: string;
    email?: string;
    role?: string;
    roles?: string[];
    permissions?: string[];
    scopes?: string[];
    scope?: string;
    tenantId?: string;
    tenantIds?: string[];
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
    audit?: AuditEmitter;
    risk?: SessionRiskReporter;
    resolveRequestContext?: (request: Request) => SessionObservation;
    sessionKeyPrefix?: string;
}
type SignablePayload = Record<string, unknown> & {
    userId?: string;
    sessionId?: string;
};
export declare class JWTService {
    private readonly expirySeconds;
    private readonly redisClient?;
    private readonly onGuestToken?;
    private readonly allowCookieAuth;
    private readonly sessionStore;
    private readonly keyRing;
    private readonly audit?;
    private readonly risk?;
    private readonly resolveRequestContext?;
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
    private correlationId;
}
export {};
//# sourceMappingURL=jwtAuth.d.ts.map