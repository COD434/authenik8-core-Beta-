import { Request, Response, NextFunction } from "express";
import { Authenik8Config } from "../types/config";
export declare const requireAdmin: (config: Authenik8Config) => (req: Request, res: Response, next: NextFunction) => Response<any, Record<string, any>> | undefined;
//# sourceMappingURL=adminService.d.ts.map