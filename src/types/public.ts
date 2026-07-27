import type { Request, RequestHandler, Response } from "express";
import type { JSONWebKeySet } from "jose" with { "resolution-mode": "import" };
import type { Redis } from "ioredis";
import type { JwtPayload } from "../auth/jwtAuth";
import type { RefreshResult } from "../auth/refreshService";
import type { SessionMetadata } from "../auth/sessionStore";
import type { AgentIdentityApi } from "../agent/types";
import type { AuditEmitter } from "../audit/types";
import type { TenantResolver } from "../authorization/types";
import type { OAuthCallbackResult } from "../oauth/types";
import type {
  SessionObservation,
  SessionRiskReporter,
} from "../risk/types";
import type { TokenPayload, TokenPair } from "./tokens";

type GitHubProvider = {
  redirect: (
    req: Request,
    res: Response,
    mode?: "login" | "link",
  ) => Promise<void>;
  handleCallback: (req: Request) => Promise<OAuthCallbackResult>;
};

type GoogleProvider = {
  redirect: (
    req: Request,
    res: Response,
    mode?: "login" | "link",
  ) => Promise<void>;
  handleCallback: (req: Request) => Promise<OAuthCallbackResult>;
};

export interface Authenik8Instance {
  signToken: (
    payload: Record<string, unknown> & {
      userId?: string;
      sessionId?: string;
    },
    observation?: SessionObservation,
  ) => Promise<string>;
  verifyToken: (token: string) => Promise<JwtPayload | null>;
  /** Verifies signature, expiry, current Redis session, and quarantine state. */
  verifyActiveToken: (token: string) => Promise<JwtPayload | null>;
  requireAuth: RequestHandler;
  guestToken: () => Promise<string>;
  getJwks: () => JSONWebKeySet;
  listSessions: (userId: string) => Promise<SessionMetadata[]>;
  revokeSession: (userId: string, sessionId: string) => Promise<void>;
  revokeAllSessions: (userId: string) => Promise<void>;
  agent?: AgentIdentityApi;
  audit: AuditEmitter;
  risk: SessionRiskReporter;

  refreshToken: (token: string) => Promise<RefreshResult>;
  generateRefreshToken: (payload: {
    userId: string;
    email: string;
    sessionId?: string;
  }) => Promise<string>;

  rateLimit: RequestHandler;
  ipWhitelist: RequestHandler;
  helmet: RequestHandler;

  addIP: (ip: string, ttlSeconds?: number) => Promise<void>;
  removeIP: (ip: string) => Promise<void>;
  listIPs: () => Promise<string[]>;

  /** @deprecated Prefer requireRole("admin"), which composes with tenant policy. */
  requireAdmin: RequestHandler;
  requireRole: (...roles: string[]) => RequestHandler;
  requirePermission: (...permissions: string[]) => RequestHandler;
  requireScope: (...scopes: string[]) => RequestHandler;
  requireTenant: (resolveTenant?: TenantResolver) => RequestHandler;
  incognito: RequestHandler;

  redisclient?: Redis;
  oauth?: {
    google?: GoogleProvider;
    github?: GitHubProvider;
  };

  issueTokens: (
    payload: TokenPayload,
    observation?: SessionObservation,
  ) => Promise<TokenPair>;
}
