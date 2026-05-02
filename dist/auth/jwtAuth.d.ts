import { Request, Response, NextFunction } from "express";
import { SignOptions } from "jsonwebtoken";
interface JwtPayload {
    userId: string;
    email: string;
    type?: string;
    id?: string;
    createdAt?: number;
}
export interface JWTOptions {
    jwtSecret: string;
    expiry?: SignOptions["expiresIn"];
    redisClient?: any;
    onGuestToken?: () => void;
}
export declare class JWTService {
    private jwtSecret;
    private expiry?;
    private redisclient?;
    private onGuestToken?;
    constructor(options: JWTOptions);
    listSessions(userId: string): Promise<any[]>;
    revokeAllSessions(userId: string): Promise<void>;
    revokeSession(userId: string, sessionId: string): Promise<void>;
    private persistSessionToken;
    signToken(payload: object, meta?: {
        device?: string;
        ip?: string;
    }): Promise<string>;
    guestToken(): string;
    verifyToken(token: string): JwtPayload | null;
    authenticateJWT: (req: Request, res: Response, next: NextFunction) => Promise<void | Response<any, Record<string, any>>>;
}
export {};
//# sourceMappingURL=jwtAuth.d.ts.map