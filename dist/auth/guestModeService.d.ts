import { Request, Response, NextFunction } from "express";
export declare const createIncognito: (options: {
    jwtSecret: string;
    guestToken: () => string;
}) => (req: Request, res: Response, next: NextFunction) => void | Response<any, Record<string, any>>;
//# sourceMappingURL=guestModeService.d.ts.map