import type { RequestHandler } from "express";
export interface RequireAdminOptions {
    /** Must enforce token purpose and active session state. */
    requireAuth: RequestHandler;
    store?: unknown;
    listSessions?: (userId: string) => Promise<unknown[]>;
    revokeSession?: (userId: string, sessionId: string) => Promise<void>;
    revokeAllSessions?: (userId: string) => Promise<void>;
}
export declare const requireAdmin: (options: RequireAdminOptions) => RequestHandler;
//# sourceMappingURL=adminService.d.ts.map