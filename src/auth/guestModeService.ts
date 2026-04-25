
import { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";

interface User {
  userId?: string;
  email?: string;
  role?: string;
  type?: "guest-mode" | "authenticated" | "guest";
  id?: string;
  createdAt?: number;
}

export const createIncognito = (options: {
  jwtSecret: string;
  guestToken: () => string;
}) => {
  return (req: Request, res: Response, next: NextFunction) => {
    const authHeader = req.headers.authorization;
    const token = authHeader?.startsWith("Bearer ")
      ? authHeader.split(" ")[1]
      : undefined;

    if (!token) {
      const guestToken = options.guestToken();
      const user = jwt.verify(guestToken, options.jwtSecret) as User;

      (req as any).user = user;
      res.setHeader("X-Guest-Token", guestToken);
      return next();
    }

    try {
      const user = jwt.verify(token, options.jwtSecret) as User;
      (req as any).user = {
        ...user,
        type: user.type ?? "authenticated",
      };
      return next();
    } catch {
      return res.status(401).json({ error: "Invalid or expired token" });
    }
  };
};
