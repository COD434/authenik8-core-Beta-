import { Request, Response, NextFunction } from "express";
import { SignOptions } from "jsonwebtoken";
import { SessionMetadata } from "./sessionStore";
interface JwtPayload {
    userId?: string;
    email?: string;
    role?: string;
    sessionId?: string;
    type?: string;
    id?: string;
    createdAt?: number;
}
export interface JWTOptions {
    jwtSecret: string;
    expiry?: SignOptions["expiresIn"];
    redisClient?: any;
    onGuestToken?: () => void;
    allowCookieAuth?: boolean;
}
type SignablePayload = Record<string, unknown> & {
    userId?: string;
    sessionId?: string;
};
export declare class JWTService {
    private readonly jwtSecret;
    private readonly expiry?;
    private readonly redisClient?;
    private readonly onGuestToken?;
    private readonly allowCookieAuth;
    private readonly sessionStore;
    constructor(options: JWTOptions);
    listSessions(userId: string): Promise<SessionMetadata[]>;
    revokeAllSessions(userId: string): Promise<void>;
    revokeSession(userId: string, sessionId: string): Promise<void>;
    signToken(payload: SignablePayload, meta?: {
        device?: string;
        ip?: string;
    }): Promise<string>;
    guestToken(): string;
    verifyToken(token: string): JwtPayload | null;
    authenticateJWT: (req: Request, res: Response, next: NextFunction) => Promise<void | Response<any, Record<string, any>>>;
    private tokenFromRequest;
    private sessionIsValid;
    private persistSessionToken;
    private tokenTtlSeconds;
}
export {};
//# sourceMappingURL=jwtAuth.d.ts.map