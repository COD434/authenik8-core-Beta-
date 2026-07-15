import type { NextFunction, Request, Response } from "express";
import { JWTService, type JwtPayload } from "./jwtAuth";

export const createIncognito = (options: {
  guestToken: () => string | Promise<string>;
  verifyAccessToken?: (token: string) => Promise<JwtPayload | null>;
  verifyGuestToken?: (token: string) => Promise<JwtPayload | null>;
  /** @deprecated Pass verifyAccessToken and verifyGuestToken from the instance. */
  jwtSecret?: string;
}) => {
  const legacyVerifier = options.jwtSecret
    ? new JWTService({ jwtSecret: options.jwtSecret })
    : undefined;
  const verifyAccessToken =
    options.verifyAccessToken ?? legacyVerifier?.verifyToken.bind(legacyVerifier);
  const verifyGuestToken =
    options.verifyGuestToken ?? legacyVerifier?.verifyGuestToken.bind(legacyVerifier);

  if (!verifyAccessToken || !verifyGuestToken) {
    throw new Error("Incognito mode requires token verification functions");
  }

  return async (req: Request, res: Response, next: NextFunction) => {
    const authHeader = req.headers.authorization;
    const token = authHeader?.startsWith("Bearer ")
      ? authHeader.slice("Bearer ".length).trim()
      : undefined;

    if (!token) {
      const guestToken = await options.guestToken();
      const user = await verifyGuestToken(guestToken);
      if (!user) {
        return res.status(500).json({ error: "Unable to issue guest token" });
      }

      (req as any).user = user;
      res.setHeader("X-Guest-Token", guestToken);
      return next();
    }

    const user = await verifyAccessToken(token);
    if (!user) {
      return res.status(401).json({ error: "Invalid or expired token" });
    }

    (req as any).user = {
      ...user,
      type: user.type ?? "authenticated",
    };
    return next();
  };
};
