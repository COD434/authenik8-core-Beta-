import type { NextFunction, Request, RequestHandler, Response } from "express";
import { JWTService } from "../auth/jwtAuth";
import { SessionStore } from "../auth/sessionStore";

const ADMIN_ONLY_ERROR = { error: "Forbidden: Admin only" };

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

export const requireAdmin = (options: RequireAdminOptions): RequestHandler => {
  const sessionStore = new SessionStore(options.store);
  const requireAuth =
    options.requireAuth ??
    new JWTService({
      jwtSecret: options.jwtSecret,
      redisClient: options.store,
      allowCookieAuth: options.allowCookieAuth,
    }).authenticateJWT;

  return async (req: Request, res: Response, next: NextFunction) => {
    return requireAuth(req, res, () => {
      const user = (req as Request & { user?: { role?: string } }).user;
      if (user?.role !== "admin") {
        return res.status(403).json(ADMIN_ONLY_ERROR);
      }

      if (options.store || options.listSessions) attachAdminActions(req, sessionStore, options);
      return next();
    });
  };
};

const attachAdminActions = (
  req: Request,
  sessionStore: SessionStore,
  options: RequireAdminOptions,
) => {
  (req as any).adminActions = {
    listSessions: (userId: string) =>
      options.listSessions?.(userId) ?? sessionStore.list(userId),
    revokeSession: (userId: string, sessionId: string) =>
      options.revokeSession?.(userId, sessionId) ?? sessionStore.revoke(userId, sessionId),
    revokeAllSessions: (userId: string) =>
      options.revokeAllSessions?.(userId) ?? sessionStore.revokeAll(userId),
  };
};
