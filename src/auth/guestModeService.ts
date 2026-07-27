import type { NextFunction, Request, Response } from "express";
import type { JwtPayload } from "./jwtAuth";

export const createIncognito = (options: {
  guestToken: () => string | Promise<string>;
  verifyAccessToken: (token: string) => Promise<JwtPayload | null>;
  verifyGuestToken: (token: string) => Promise<JwtPayload | null>;
}) => {
  if (
    typeof options.guestToken !== "function" ||
    typeof options.verifyAccessToken !== "function" ||
    typeof options.verifyGuestToken !== "function"
  ) {
    throw new Error(
      "Incognito mode requires issuance and purpose-bound verification functions",
    );
  }

  return async (req: Request, res: Response, next: NextFunction) => {
    const authorization = req.headers.authorization;
    const match =
      typeof authorization === "string" &&
      authorization.length <= 16 * 1024 + 16
        ? /^Bearer ([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)$/i.exec(
            authorization,
          )
        : null;

    if (authorization && !match) {
      return res.status(401).json({ error: "Invalid authorization header" });
    }
    const token = match?.[1];
    if (!token) {
      const guestToken = await options.guestToken();
      const user = await options.verifyGuestToken(guestToken);
      if (!user) {
        return res.status(500).json({ error: "Unable to issue guest token" });
      }

      (req as any).user = user;
      res.setHeader("X-Guest-Token", guestToken);
      return next();
    }

    const user = await options.verifyAccessToken(token);
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
