import type { RequestHandler } from "express";
export interface RequireAdminOptions {
    requireAuth?: RequestHandler;
    /** @deprecated Pass the instance's session-aware `requireAuth` middleware. */
    jwtSecret?: string;
    store?: any;
    allowCookieAuth?: boolean;
    listSessions?: (userId: string) => Promise<unknown[]>;
    revokeSession?: (userId: string, sessionId: string) => Promise<void>;
    revokeAllSessions?: (userId: string) => Promise<void>;
}
export declare const requireAdmin: (options: RequireAdminOptions) => RequestHandler;
//# sourceMappingURL=adminService.d.ts.map