import type { NextFunction, Request, RequestHandler, Response } from "express";
import { SessionStore } from "../auth/sessionStore";

const ADMIN_ONLY_ERROR = { error: "Forbidden: Admin only" };

export interface RequireAdminOptions {
  /** Must enforce token purpose and active session state. */
  requireAuth: RequestHandler;
  store?: unknown;
  listSessions?: (userId: string) => Promise<unknown[]>;
  revokeSession?: (userId: string, sessionId: string) => Promise<void>;
  revokeAllSessions?: (userId: string) => Promise<void>;
}

export const requireAdmin = (options: RequireAdminOptions): RequestHandler => {
  if (typeof options.requireAuth !== "function") {
    throw new Error("requireAdmin requires session-aware requireAuth middleware");
  }
  const sessionStore = new SessionStore(options.store as never);

  return async (req: Request, res: Response, next: NextFunction) =>
    options.requireAuth(req, res, () => {
      const user = (req as Request & { user?: { role?: unknown } }).user;
      if (user?.role !== "admin") {
        return res.status(403).json(ADMIN_ONLY_ERROR);
      }

      if (
        options.store ||
        options.listSessions ||
        options.revokeSession ||
        options.revokeAllSessions
      ) {
        attachAdminActions(req, sessionStore, options);
      }
      return next();
    });
};

const attachAdminActions = (
  req: Request,
  sessionStore: SessionStore,
  options: RequireAdminOptions,
) => {
  (
    req as Request & {
      adminActions?: {
        listSessions(userId: string): Promise<unknown[]>;
        revokeSession(userId: string, sessionId: string): Promise<void>;
        revokeAllSessions(userId: string): Promise<void>;
      };
    }
  ).adminActions = {
    listSessions: (userId: string) =>
      options.listSessions?.(userId) ?? sessionStore.list(userId),
    revokeSession: (userId: string, sessionId: string) =>
      options.revokeSession?.(userId, sessionId) ??
      sessionStore.revoke(userId, sessionId),
    revokeAllSessions: (userId: string) =>
      options.revokeAllSessions?.(userId) ?? sessionStore.revokeAll(userId),
  };
};
