import crypto from "crypto";
import type { NextFunction, Request, Response } from "express";
import type { Authenik8JwkConfig } from "./jwk";
import { JwtKeyRing, normalizeTokenLifetime } from "./jwk";
import {
  SessionMetadata,
  SessionStore,
  sessionTokenMatches,
} from "./sessionStore";
import type { AuditEmitter } from "../audit/types";
import type {
  SessionObservation,
  SessionRiskReporter,
} from "../risk/types";
import { markAuthenik8Authenticated } from "./requestIdentity";
import { containsControlCharacter } from "../utility/safeString";

export interface JwtPayload {
  [key: string]: unknown;
  userId?: string;
  email?: string;
  role?: string;
  roles?: string[];
  permissions?: string[];
  scopes?: string[];
  scope?: string;
  tenantId?: string;
  tenantIds?: string[];
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
  audit?: AuditEmitter;
  risk?: SessionRiskReporter;
  resolveRequestContext?: (request: Request) => SessionObservation;
  sessionKeyPrefix?: string;
}

type SignablePayload = Record<string, unknown> & {
  userId?: string;
  sessionId?: string;
};

const ACCESS_TOKEN_FALLBACK_EXPIRY = "1h";
const MAX_ACCESS_TOKEN_TTL_SECONDS = 24 * 60 * 60;
const INVALID_SESSION_RESPONSE = {
  success: false,
  message: "invalid session",
  errors: [],
};
const MAX_ACCESS_PAYLOAD_BYTES = 8 * 1024;
const MAX_IDENTITY_CLAIM_LENGTH = 256;
const MAX_AUTHORIZATION_CLAIMS = 64;
const MAX_AUTHORIZATION_CLAIM_LENGTH = 128;

const assertOptionalClaim = (
  value: unknown,
  label: string,
  maximumLength: number,
): void => {
  if (
    value !== undefined &&
    (typeof value !== "string" ||
      value.length === 0 ||
      value.length > maximumLength ||
      containsControlCharacter(value))
  ) {
    throw new Error(`${label} is invalid`);
  }
};

const assertOptionalClaimArray = (
  value: unknown,
  label: string,
): void => {
  if (value === undefined) return;
  if (
    !Array.isArray(value) ||
    value.length > MAX_AUTHORIZATION_CLAIMS ||
    value.some(
      (entry) =>
        typeof entry !== "string" ||
        entry.length === 0 ||
        entry.length > MAX_AUTHORIZATION_CLAIM_LENGTH ||
        containsControlCharacter(entry),
    )
  ) {
    throw new Error(
      `${label} must contain at most ${MAX_AUTHORIZATION_CLAIMS} safe strings of at most ${MAX_AUTHORIZATION_CLAIM_LENGTH} characters`,
    );
  }
};

const validateAccessClaims = (payload: SignablePayload): void => {
  assertOptionalClaim(payload.userId, "userId", MAX_IDENTITY_CLAIM_LENGTH);
  assertOptionalClaim(payload.sessionId, "sessionId", MAX_IDENTITY_CLAIM_LENGTH);
  assertOptionalClaim(payload.email, "email", 254);
  assertOptionalClaim(payload.role, "role", MAX_AUTHORIZATION_CLAIM_LENGTH);
  assertOptionalClaim(
    payload.scope,
    "scope",
    MAX_AUTHORIZATION_CLAIMS *
      (MAX_AUTHORIZATION_CLAIM_LENGTH + 1),
  );
  assertOptionalClaim(
    payload.tenantId,
    "tenantId",
    MAX_IDENTITY_CLAIM_LENGTH,
  );
  assertOptionalClaimArray(payload.roles, "roles");
  assertOptionalClaimArray(payload.permissions, "permissions");
  assertOptionalClaimArray(payload.scopes, "scopes");
  assertOptionalClaimArray(payload.tenantIds, "tenantIds");
};

const validateAccessPayload = (payload: SignablePayload): void => {
  validateAccessClaims(payload);
  let serialized: string;
  try {
    serialized = JSON.stringify(payload);
  } catch {
    throw new Error("Access token payload must be JSON serializable");
  }
  if (Buffer.byteLength(serialized, "utf8") > MAX_ACCESS_PAYLOAD_BYTES) {
    throw new Error(
      `Access token payload must not exceed ${MAX_ACCESS_PAYLOAD_BYTES} bytes`,
    );
  }
};

export class JWTService {
  private readonly expirySeconds: number;
  private readonly redisClient?: any;
  private readonly onGuestToken?: () => void;
  private readonly allowCookieAuth: boolean;
  private readonly sessionStore: SessionStore;
  private readonly keyRing: JwtKeyRing;
  private readonly audit?: AuditEmitter;
  private readonly risk?: SessionRiskReporter;
  private readonly resolveRequestContext?: JWTOptions["resolveRequestContext"];

  constructor(options: JWTOptions) {
    if (
      options.allowCookieAuth !== undefined &&
      typeof options.allowCookieAuth !== "boolean"
    ) {
      throw new Error("allowCookieAuth must be a boolean");
    }
    this.expirySeconds = normalizeTokenLifetime(
      options.expiry ?? ACCESS_TOKEN_FALLBACK_EXPIRY,
      "jwtExpiry",
      60,
      MAX_ACCESS_TOKEN_TTL_SECONDS,
    );
    this.redisClient = options.redisClient;
    this.onGuestToken = options.onGuestToken;
    this.allowCookieAuth = options.allowCookieAuth ?? false;
    this.audit = options.audit;
    this.risk = options.risk;
    this.resolveRequestContext = options.resolveRequestContext;
    this.sessionStore = new SessionStore(
      options.redisClient,
      options.sessionKeyPrefix ?? "sessions",
    );
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
    await this.audit?.emit({
      type: "session.revoked_all",
      severity: "warning",
      outcome: "success",
      actor: { type: "system" },
      subject: { type: "user", id: userId },
    });
  }

  async revokeSession(userId: string, sessionId: string) {
    await this.sessionStore.revoke(userId, sessionId);
    await this.audit?.emit({
      type: "session.revoked",
      severity: "warning",
      outcome: "success",
      actor: { type: "system" },
      subject: { type: "user", id: userId },
      sessionId,
    });
  }

  async signToken(
    payload: SignablePayload,
    meta?: { device?: string; ip?: string },
  ): Promise<string> {
    validateAccessPayload(payload);
    const sessionId = payload.sessionId ?? crypto.randomUUID();
    const fullPayload = { ...payload, sessionId };
    const token = await this.keyRing.sign(fullPayload, {
      expiresInSeconds: this.expirySeconds,
      tokenUse: "access",
    });

    await this.persistSessionToken(fullPayload, token, {
      sessionId,
      device: meta?.device || "unknown",
      ip: meta?.ip || "unknown",
      createdAt: Date.now(),
    });
    try {
      await this.audit?.emit({
        type: "access_token.issued",
        severity: "info",
        outcome: "success",
        actor: { type: "system" },
        subject: payload.userId
          ? { type: "user", id: payload.userId }
          : { type: "unknown" },
        sessionId,
        ...(typeof payload.tenantId === "string"
          ? { tenantId: payload.tenantId }
          : {}),
      });
    } catch (error) {
      if (payload.userId) {
        await this.sessionStore.revoke(payload.userId, sessionId);
      }
      throw error;
    }

    return token;
  }

  async guestToken(): Promise<string> {
    const payload = {
      type: "guest",
      id: crypto.randomUUID(),
      createdAt: Date.now(),
    };

    this.onGuestToken?.();
    const token = await this.keyRing.sign(payload, {
      expiresInSeconds: this.expirySeconds,
      tokenUse: "guest",
    });
    await this.audit?.emit({
      type: "guest_token.issued",
      severity: "info",
      outcome: "success",
      actor: { type: "system" },
      subject: { type: "guest", id: payload.id },
    });
    return token;
  }

  async verifyToken(token: string): Promise<JwtPayload | null> {
    try {
      const payload = await this.keyRing.verify<JwtPayload>(token, "access");
      validateAccessClaims(payload);
      return payload;
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
    const session = await this.sessionStore.get(userId, sessionId);
    if (!session) return false;
    return !(
      await this.risk?.isQuarantined({
        kind: "human",
        id: userId,
        sessionId,
      })
    );
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
      await this.audit?.emit({
        type: "access_token.rejected",
        severity: "warning",
        outcome: "denied",
        actor: { type: "unknown" },
        correlationId: this.correlationId(req),
        metadata: { reason: "missing" },
      });
      return res.status(401).json({ message: "Unauthorized" });
    }

    const decoded = await this.verifyToken(token);
    if (!decoded) {
      await this.audit?.emit({
        type: "access_token.rejected",
        severity: "warning",
        outcome: "denied",
        actor: { type: "unknown" },
        correlationId: this.correlationId(req),
        metadata: { reason: "invalid_or_expired" },
      });
      return res
        .status(403)
        .json({ success: false, message: "invalid or expired token" });
    }

    if (this.redisClient) {
      const sessionIsValid = await this.sessionIsValid(
        decoded,
        token,
        this.resolveRequestContext?.(req),
      );
      if (!sessionIsValid) {
        await this.audit?.emit({
          type: "access_token.rejected",
          severity: "warning",
          outcome: "denied",
          actor: {
            type: "user",
            ...(decoded.userId ? { id: decoded.userId } : {}),
          },
          ...(decoded.sessionId ? { sessionId: decoded.sessionId } : {}),
          correlationId: this.correlationId(req),
          metadata: { reason: "inactive_or_quarantined_session" },
        });
        return res.status(403).json(INVALID_SESSION_RESPONSE);
      }
    }

    (req as any).user = decoded;
    markAuthenik8Authenticated(req);
    return next();
  };

  private tokenFromRequest(req: Request): string | undefined {
    const authHeader = req.headers.authorization;
    const match =
      typeof authHeader === "string" && authHeader.length <= 16 * 1024 + 16
        ? /^Bearer ([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)$/i.exec(
            authHeader,
          )
        : null;
    const bearerToken = match?.[1];
    const rawCookieToken = this.allowCookieAuth ? req.cookies?.token : undefined;
    const cookieToken =
      typeof rawCookieToken === "string" &&
      rawCookieToken.length <= 16 * 1024
        ? rawCookieToken
        : undefined;
    if (bearerToken && cookieToken && bearerToken !== cookieToken) {
      return undefined;
    }
    return bearerToken ?? cookieToken;
  }

  private async sessionIsValid(
    decoded: JwtPayload,
    token: string,
    observed?: SessionObservation,
  ): Promise<boolean> {
    if (!decoded.userId || !decoded.sessionId) return false;
    const session = await this.sessionStore.get(decoded.userId, decoded.sessionId);
    if (!session || !sessionTokenMatches(session, token)) return false;

    const principal = {
      kind: "human" as const,
      id: decoded.userId,
      sessionId: decoded.sessionId,
    };
    if (await this.risk?.isQuarantined(principal)) return false;
    if (observed && this.risk) {
      const state = await this.risk.assessContext(
        principal,
        { ip: session.ip, device: session.device },
        observed,
      );
      if (state.status === "quarantined") return false;
    }
    return true;
  }

  private async persistSessionToken(
    payload: SignablePayload,
    token: string,
    metadata: SessionMetadata,
  ): Promise<void> {
    if (!this.redisClient || !payload.userId) return;

    await this.sessionStore.updateToken(
      payload.userId,
      metadata.sessionId,
      token,
      this.expirySeconds,
      metadata,
    );
  }

  private correlationId(req: Request): string | undefined {
    const value = req.headers["x-request-id"];
    return typeof value === "string" &&
      value.length > 0 &&
      value.length <= 128 &&
      !containsControlCharacter(value)
      ? value
      : undefined;
  }
}
