import type { NextFunction, Request, Response } from "express";
import { type JwtPayload } from "./jwtAuth";
export declare const createIncognito: (options: {
    guestToken: () => string | Promise<string>;
    verifyAccessToken?: (token: string) => Promise<JwtPayload | null>;
    verifyGuestToken?: (token: string) => Promise<JwtPayload | null>;
    /** @deprecated Pass verifyAccessToken and verifyGuestToken from the instance. */
    jwtSecret?: string;
}) => (req: Request, res: Response, next: NextFunction) => Promise<void | Response<any, Record<string, any>>>;
//# sourceMappingURL=guestModeService.d.ts.map