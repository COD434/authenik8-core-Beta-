import { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";
import { SignOptions } from "jsonwebtoken";
import crypto from "crypto";
import { SessionMetadata, SessionStore } from "./sessionStore";

interface JwtPayload {
  userId?: string;
  email?: string;
  role?: string;
  sessionId?: string;
  type?: string;
  id?: string;
  createdAt?: number;
}

export interface JWTOptions {
  jwtSecret: string;
  expiry?: SignOptions["expiresIn"];
  redisClient?: any;
  onGuestToken?: () => void;
  allowCookieAuth?: boolean;
}

type SignablePayload = Record<string, unknown> & {
  userId?: string;
  sessionId?: string;
};

const ACCESS_TOKEN_FALLBACK_EXPIRY: SignOptions["expiresIn"] = "1h";
const SESSION_TTL_FALLBACK_SECONDS = 3600;
const INVALID_SESSION_RESPONSE = {
  success: false,
  message: "invalid session",
  errors: [],
};

export class JWTService {
  private readonly jwtSecret: string;
  private readonly expiry?: SignOptions["expiresIn"];
  private readonly redisClient?: any;
  private readonly onGuestToken?: () => void;
  private readonly allowCookieAuth: boolean;
  private readonly sessionStore: SessionStore;

  constructor(options: JWTOptions) {
    this.jwtSecret = options.jwtSecret;
    this.expiry = options.expiry;
    this.redisClient = options.redisClient;
    this.onGuestToken = options.onGuestToken;
    this.allowCookieAuth = options.allowCookieAuth ?? false;
    this.sessionStore = new SessionStore(options.redisClient);
  }

  async listSessions(userId: string) {
    return this.sessionStore.list(userId);
  }

  async revokeAllSessions(userId: string): Promise<void> {
    await this.sessionStore.revokeAll(userId);
  }

  async revokeSession(userId: string, sessionId: string) {
    await this.sessionStore.revoke(userId, sessionId);
  }

  async signToken(
    payload: SignablePayload,
    meta?: { device?: string; ip?: string }
  ): Promise<string> {
    const sessionId = payload.sessionId ?? crypto.randomUUID();
    const fullPayload = { ...payload, sessionId };
    const token = jwt.sign(fullPayload, this.jwtSecret, {
      expiresIn: this.expiry || ACCESS_TOKEN_FALLBACK_EXPIRY,
    });

    await this.persistSessionToken(fullPayload, token, {
      sessionId,
      device: meta?.device || "unknown",
      ip: meta?.ip || "unknown",
      createdAt: Date.now(),
    });

    return token;
  }

  guestToken(): string {
    const payload = {
      type: "guest",
      id: crypto.randomUUID(),
      createdAt: Date.now(),
    };

    if (this.onGuestToken) {
      this.onGuestToken();
    }

    return jwt.sign(payload, this.jwtSecret, { expiresIn: this.expiry });
  }

  verifyToken(token: string): JwtPayload | null {
    try {
      return jwt.verify(token, this.jwtSecret) as JwtPayload;
    } catch {
      return null;
    }
  }

  authenticateJWT = async (
    req: Request,
    res: Response,
    next: NextFunction
  ) => {
    const token = this.tokenFromRequest(req);

    if (!token) {
      return res.status(401).json({ message: "Unauthorized" });
    }

    try {
      const decoded = jwt.verify(token, this.jwtSecret) as JwtPayload;

      if (this.redisClient) {
        const sessionIsValid = await this.sessionIsValid(decoded, token);
        if (!sessionIsValid) {
          return res.status(403).json(INVALID_SESSION_RESPONSE);
        }
      }

      (req as any).user = decoded;
      return next();
    } catch {
      return res
        .status(403)
        .json({ success: false, message: "invalid or expired token" });
    }
  };

  private tokenFromRequest(req: Request): string | undefined {
    const authHeader = req.headers.authorization;
    const bearerToken = authHeader?.startsWith("Bearer ")
      ? authHeader.split(" ")[1]
      : undefined;
    const cookieToken = this.allowCookieAuth ? req.cookies?.token : undefined;

    return bearerToken || cookieToken;
  }

  private async sessionIsValid(
    decoded: JwtPayload,
    token: string
  ): Promise<boolean> {
    if (!decoded.userId || !decoded.sessionId) {
      return false;
    }

    return this.sessionStore.tokenMatches(
      decoded.userId,
      decoded.sessionId,
      token
    );
  }

  private async persistSessionToken(
    payload: SignablePayload,
    token: string,
    metadata: SessionMetadata
  ): Promise<void> {
    if (!this.redisClient || !payload.userId) return;

    try {
      const ttl = this.tokenTtlSeconds(token);
      await this.sessionStore.upsert(payload.userId, token, metadata, ttl);
    } catch {
      // Session persistence must not make token signing fail.
    }
  }

  private tokenTtlSeconds(token: string): number {
    const decoded = jwt.decode(token) as { exp?: number } | null;
    const now = Math.floor(Date.now() / 1000);

    return decoded?.exp
      ? Math.max(decoded.exp - now, 1)
      : SESSION_TTL_FALLBACK_SECONDS;
  }
}
