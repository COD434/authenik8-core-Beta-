import crypto from "crypto";
import type { NextFunction, Request, Response } from "express";
import type { Authenik8JwkConfig } from "./jwk";
import { JwtKeyRing, loadJose } from "./jwk";
import { SessionMetadata, SessionStore } from "./sessionStore";

export interface JwtPayload {
  [key: string]: unknown;
  userId?: string;
  email?: string;
  role?: string;
  sessionId?: string;
  type?: string;
  id?: string;
  createdAt?: number;
  tokenUse?: string;
  exp?: number;
  iat?: number;
  iss?: string;
  aud?: string | string[];
  jti?: string;
}

export interface JWTOptions {
  jwtSecret?: string;
  jwk?: Authenik8JwkConfig;
  issuer?: string;
  audience?: string | string[];
  expiry?: string | number;
  redisClient?: any;
  onGuestToken?: () => void;
  allowCookieAuth?: boolean;
}

type SignablePayload = Record<string, unknown> & {
  userId?: string;
  sessionId?: string;
};

const ACCESS_TOKEN_FALLBACK_EXPIRY = "1h";
const SESSION_TTL_FALLBACK_SECONDS = 3600;
const INVALID_SESSION_RESPONSE = {
  success: false,
  message: "invalid session",
  errors: [],
};

export class JWTService {
  private readonly expiry: string | number;
  private readonly redisClient?: any;
  private readonly onGuestToken?: () => void;
  private readonly allowCookieAuth: boolean;
  private readonly sessionStore: SessionStore;
  private readonly keyRing: JwtKeyRing;

  constructor(options: JWTOptions) {
    this.expiry = options.expiry ?? ACCESS_TOKEN_FALLBACK_EXPIRY;
    this.redisClient = options.redisClient;
    this.onGuestToken = options.onGuestToken;
    this.allowCookieAuth = options.allowCookieAuth ?? false;
    this.sessionStore = new SessionStore(options.redisClient);
    this.keyRing = new JwtKeyRing({
      jwk: options.jwk,
      legacySecret: options.jwtSecret,
      issuer: options.issuer,
      audience: options.audience,
    });
  }

  get issuer(): string {
    return this.keyRing.issuer;
  }

  get audience(): string | string[] {
    return this.keyRing.audience;
  }

  getJwks() {
    return this.keyRing.getJwks();
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
    meta?: { device?: string; ip?: string },
  ): Promise<string> {
    const sessionId = payload.sessionId ?? crypto.randomUUID();
    const fullPayload = { ...payload, sessionId };
    const token = await this.keyRing.sign(fullPayload, {
      expiresIn: this.expiry,
      tokenUse: "access",
    });

    await this.persistSessionToken(fullPayload, token, {
      sessionId,
      device: meta?.device || "unknown",
      ip: meta?.ip || "unknown",
      createdAt: Date.now(),
    });

    return token;
  }

  async guestToken(): Promise<string> {
    const payload = {
      type: "guest",
      id: crypto.randomUUID(),
      createdAt: Date.now(),
    };

    this.onGuestToken?.();

    return this.keyRing.sign(payload, {
      expiresIn: this.expiry,
      tokenUse: "guest",
    });
  }

  async verifyToken(token: string): Promise<JwtPayload | null> {
    try {
      return await this.keyRing.verify<JwtPayload>(token, "access");
    } catch {
      return null;
    }
  }

  async verifyActiveToken(token: string): Promise<JwtPayload | null> {
    const decoded = await this.verifyToken(token);
    if (!decoded) return null;
    if (!this.redisClient) return decoded;
    return (await this.sessionIsValid(decoded, token)) ? decoded : null;
  }

  async hasActiveSession(userId: string, sessionId: string): Promise<boolean> {
    if (!this.redisClient) return false;
    return !!(await this.sessionStore.get(userId, sessionId));
  }

  async verifyGuestToken(token: string): Promise<JwtPayload | null> {
    try {
      return await this.keyRing.verify<JwtPayload>(token, "guest");
    } catch {
      return null;
    }
  }

  authenticateJWT = async (
    req: Request,
    res: Response,
    next: NextFunction,
  ) => {
    const token = this.tokenFromRequest(req);

    if (!token) {
      return res.status(401).json({ message: "Unauthorized" });
    }

    const decoded = await this.verifyToken(token);
    if (!decoded) {
      return res
        .status(403)
        .json({ success: false, message: "invalid or expired token" });
    }

    if (this.redisClient) {
      const sessionIsValid = await this.sessionIsValid(decoded, token);
      if (!sessionIsValid) {
        return res.status(403).json(INVALID_SESSION_RESPONSE);
      }
    }

    (req as any).user = decoded;
    return next();
  };

  private tokenFromRequest(req: Request): string | undefined {
    const authHeader = req.headers.authorization;
    const bearerToken = authHeader?.startsWith("Bearer ")
      ? authHeader.slice("Bearer ".length).trim()
      : undefined;
    const cookieToken = this.allowCookieAuth ? req.cookies?.token : undefined;

    return bearerToken || cookieToken;
  }

  private async sessionIsValid(
    decoded: JwtPayload,
    token: string,
  ): Promise<boolean> {
    if (!decoded.userId || !decoded.sessionId) return false;
    return this.sessionStore.tokenMatches(decoded.userId, decoded.sessionId, token);
  }

  private async persistSessionToken(
    payload: SignablePayload,
    token: string,
    metadata: SessionMetadata,
  ): Promise<void> {
    if (!this.redisClient || !payload.userId) return;

    try {
      const { decodeJwt } = await loadJose();
      const decoded = decodeJwt(token);
      const now = Math.floor(Date.now() / 1000);
      const ttl = decoded.exp
        ? Math.max(decoded.exp - now, 1)
        : SESSION_TTL_FALLBACK_SECONDS;
      await this.sessionStore.upsert(payload.userId, token, metadata, ttl);
    } catch {
      // Session persistence must not make token signing fail.
    }
  }
}
