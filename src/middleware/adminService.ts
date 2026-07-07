import { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";
import { RequireAdminOptions } from "../types/admin";
import { SessionStore } from "../auth/sessionStore";

interface JwtPayload {
  userId?: string;
  role?: string;
  sessionId?: string;
}

const ADMIN_ONLY_ERROR = { error: "Forbidden: Admin only" };
const INVALID_ADMIN_SESSION_ERROR = {
  error: "Forbidden: invalid admin session",
};

export const requireAdmin = (options: RequireAdminOptions) => {
  const sessionStore = new SessionStore(options.store);

  return async (req: Request, res: Response, next: NextFunction) => {
    const token = tokenFromRequest(req, options.allowCookieAuth ?? false);

    if (!token) {
      return res.status(401).json({ error: "Unauthorized:No token provided" });
    }

    try {
      const decoded = jwt.verify(token, options.jwtSecret) as JwtPayload;

      if (decoded.role !== "admin") {
        return res.status(403).json(ADMIN_ONLY_ERROR);
      }

      if (options.store) {
        const sessionIsValid = await adminSessionIsValid(
          sessionStore,
          decoded,
          token
        );

        if (!sessionIsValid) {
          return res.status(403).json(INVALID_ADMIN_SESSION_ERROR);
        }

        attachAdminActions(req, sessionStore);
      }

      (req as any).user = decoded;
      return next();
    } catch {
      return res.status(401).json({ error: "Invalid or expired token" });
    }
  };
};

const tokenFromRequest = (
  req: Request,
  allowCookieAuth: boolean
): string | undefined => {
  const authHeader = req.headers.authorization;
  const bearerToken = authHeader?.startsWith("Bearer ")
    ? authHeader.split(" ")[1]
    : undefined;
  const cookieToken = allowCookieAuth ? req.cookies?.token : undefined;

  return bearerToken || cookieToken;
};

const adminSessionIsValid = async (
  sessionStore: SessionStore,
  decoded: JwtPayload,
  token: string
): Promise<boolean> => {
  if (!decoded.userId || !decoded.sessionId) {
    return false;
  }

  return sessionStore.tokenMatches(decoded.userId, decoded.sessionId, token);
};

const attachAdminActions = (req: Request, sessionStore: SessionStore) => {
  (req as any).adminActions = {
    listSessions: (userId: string) => sessionStore.list(userId),
    revokeSession: (userId: string, sessionId: string) =>
      sessionStore.revoke(userId, sessionId),
    revokeAllSessions: (userId: string) => sessionStore.revokeAll(userId),
  };
};
