import { randomUUID } from "crypto";
import type { NextFunction, Request, Response } from "express";
import type { Authenik8JwkConfig } from "../auth/jwk";
import { JwtKeyRing, loadJose } from "../auth/jwk";
import type { JwtPayload } from "../auth/jwtAuth";
import { SessionStore } from "../auth/sessionStore";
import type {
  AgentIdentityApi,
  AgentIdentityConfig,
  AgentAuthenticatedRequest,
  AgentSessionMetadata,
  AgentTokenPayload,
  AgentTokenResult,
  AgentTokenUse,
  IssueAgentTokenInput,
  IssueDelegatedAgentTokenInput,
  RegisteredAgentIdentity,
} from "./types";

const DEFAULT_AGENT_TOKEN_EXPIRY = "15m";
const AGENT_SESSION_NAMESPACE = "agent-sessions";
const AGENT_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const SCOPE_PATTERN = /^[a-z][a-z0-9._/-]*(?::[a-z][a-z0-9._/-]*)+$/;
const MAX_SCOPES = 64;

type AgentRedisClient = {
  hget?: (key: string, field: string) => Promise<string | null>;
  hgetall?: (key: string) => Promise<Record<string, string> | null>;
  hset?: (key: string, field: string, value: string) => Promise<unknown>;
  hdel?: (key: string, field: string) => Promise<unknown>;
  expire?: (key: string, seconds: number) => Promise<unknown>;
  exists?: (key: string) => Promise<number>;
  set?: (key: string, value: string) => Promise<unknown>;
  del?: (key: string) => Promise<unknown>;
};

export interface AgentIdentityServiceOptions {
  config: AgentIdentityConfig;
  redisClient: AgentRedisClient;
  jwk?: Authenik8JwkConfig;
  legacySecret?: string;
  issuer: string;
  audience: string | string[];
  verifyHumanToken: (token: string) => Promise<JwtPayload | null>;
  hasHumanSession: (userId: string, sessionId: string) => Promise<boolean>;
}

export class AgentIdentityError extends Error {
  constructor(
    readonly code:
      | "AGENT_INVALID"
      | "AGENT_REVOKED"
      | "AGENT_SCOPE_DENIED"
      | "AGENT_DELEGATION_DENIED"
      | "AGENT_SESSION_REQUIRED",
    message: string,
  ) {
    super(message);
    this.name = "AgentIdentityError";
  }
}

const assertAgentId = (agentId: string): string => {
  if (!AGENT_ID_PATTERN.test(agentId)) {
    throw new AgentIdentityError(
      "AGENT_INVALID",
      "agentId must be 1-128 letters, numbers, dots, underscores, or hyphens",
    );
  }
  return agentId;
};

const normalizeScopes = (scopes: readonly string[]): string[] => {
  const normalized = [...new Set(scopes)];
  if (!normalized.length || normalized.length > MAX_SCOPES) {
    throw new AgentIdentityError(
      "AGENT_SCOPE_DENIED",
      `Agent tokens require between 1 and ${MAX_SCOPES} scopes`,
    );
  }
  if (
    normalized.some(
      (scope) => scope.length > 128 || !SCOPE_PATTERN.test(scope),
    )
  ) {
    throw new AgentIdentityError(
      "AGENT_SCOPE_DENIED",
      "Agent scopes must be at most 128 characters and use lower-case resource:action names",
    );
  }
  return normalized.sort();
};

const scopesAreAllowed = (
  requested: readonly string[],
  allowed: readonly string[],
): boolean => {
  const allowedSet = new Set(allowed);
  return requested.every((scope) => allowedSet.has(scope));
};

export class AgentIdentityService implements AgentIdentityApi {
  private readonly config: AgentIdentityConfig;
  private readonly redis: AgentRedisClient;
  private readonly keyRing: JwtKeyRing;
  private readonly sessions: SessionStore;
  private readonly verifyHumanToken: AgentIdentityServiceOptions["verifyHumanToken"];
  private readonly hasHumanSession: AgentIdentityServiceOptions["hasHumanSession"];

  constructor(options: AgentIdentityServiceOptions) {
    if (
      !options.redisClient.hget ||
      !options.redisClient.hset ||
      !options.redisClient.hdel ||
      !options.redisClient.del ||
      !options.redisClient.expire ||
      !options.redisClient.exists ||
      !options.redisClient.set
    ) {
      throw new AgentIdentityError(
        "AGENT_SESSION_REQUIRED",
        "Agent identity requires Redis hash, expiry, existence, set, and delete operations",
      );
    }

    this.config = options.config;
    this.redis = options.redisClient;
    this.sessions = new SessionStore(options.redisClient, AGENT_SESSION_NAMESPACE);
    this.verifyHumanToken = options.verifyHumanToken;
    this.hasHumanSession = options.hasHumanSession;
    this.keyRing = new JwtKeyRing({
      jwk: options.jwk,
      legacySecret: options.legacySecret,
      issuer: options.issuer,
      audience: options.audience,
    });
  }

  async issueToken(input: IssueAgentTokenInput): Promise<AgentTokenResult> {
    const agent = await this.resolveActiveAgent(input.agentId);
    const scopes = this.authorizedScopes(agent, input.scopes ?? agent.scopes);
    return this.issue(agent, scopes, "agent", input);
  }

  async issueDelegatedToken(
    input: IssueDelegatedAgentTokenInput,
  ): Promise<AgentTokenResult> {
    const agent = await this.resolveActiveAgent(input.agentId);
    const scopes = this.authorizedScopes(agent, input.scopes);
    const user = await this.verifyHumanToken(input.userAccessToken);

    if (!user?.userId || !user.sessionId) {
      throw new AgentIdentityError(
        "AGENT_DELEGATION_DENIED",
        "Delegation requires an active human access-token session",
      );
    }

    const sessionActive = await this.hasHumanSession(user.userId, user.sessionId);
    if (!sessionActive) {
      throw new AgentIdentityError(
        "AGENT_DELEGATION_DENIED",
        "The delegating human session is no longer active",
      );
    }

    const authorized = this.config.authorizeDelegation
      ? await this.config.authorizeDelegation({
          agent,
          user: user as JwtPayload & { userId: string; sessionId: string },
          requestedScopes: scopes,
        })
      : false;
    if (!authorized) {
      throw new AgentIdentityError(
        "AGENT_DELEGATION_DENIED",
        "Agent delegation was denied by application policy",
      );
    }

    return this.issue(agent, scopes, "agent-delegation", input, user);
  }

  async verifyToken(token: string): Promise<AgentTokenPayload | null> {
    try {
      const { decodeJwt } = await loadJose();
      const unverifiedUse = decodeJwt(token).tokenUse;
      if (unverifiedUse !== "agent" && unverifiedUse !== "agent-delegation") {
        return null;
      }

      const payload = await this.keyRing.verify<AgentTokenPayload>(
        token,
        unverifiedUse,
      );
      if (!this.claimsAreValid(payload)) return null;
      if (await this.isRevoked(payload.agentId)) return null;
      if (
        !(await this.sessions.tokenMatches(
          payload.agentId,
          payload.sessionId,
          token,
        ))
      ) {
        return null;
      }

      const agent = await this.resolveActiveAgent(payload.agentId);
      const allowedScopes = normalizeScopes(agent.scopes);
      if (!scopesAreAllowed(payload.scopes, allowedScopes)) return null;

      if (
        payload.tokenUse === "agent-delegation" &&
        !(await this.hasHumanSession(
          payload.delegatedUserId!,
          payload.delegatedSessionId!,
        ))
      ) {
        return null;
      }

      return payload;
    } catch {
      return null;
    }
  }

  requireAgent = async (req: Request, res: Response, next: NextFunction) => {
    return this.authenticate(req, res, next, []);
  };

  requireScopes(...scopes: string[]) {
    const requiredScopes = normalizeScopes(scopes);
    return async (req: Request, res: Response, next: NextFunction) =>
      this.authenticate(req, res, next, requiredScopes);
  }

  async listSessions(agentId: string): Promise<AgentSessionMetadata[]> {
    const sessions = await this.sessions.list(assertAgentId(agentId));
    return sessions.map(({ sessionId, device, ip, createdAt }) => ({
      sessionId,
      label: device,
      ip,
      createdAt,
    }));
  }

  async revokeSession(agentId: string, sessionId: string): Promise<void> {
    await this.sessions.revoke(assertAgentId(agentId), assertAgentId(sessionId));
  }

  async revokeAgent(agentId: string): Promise<void> {
    const validAgentId = assertAgentId(agentId);
    await this.redis.set!(this.revokedKey(validAgentId), "1");
    await this.sessions.revokeAll(validAgentId);
  }

  async activateAgent(agentId: string): Promise<void> {
    await this.redis.del!(this.revokedKey(assertAgentId(agentId)));
  }

  private async issue(
    agent: RegisteredAgentIdentity,
    scopes: string[],
    tokenUse: AgentTokenUse,
    input: IssueAgentTokenInput | IssueDelegatedAgentTokenInput,
    user?: JwtPayload,
  ): Promise<AgentTokenResult> {
    const sessionId = input.sessionId
      ? assertAgentId(input.sessionId)
      : randomUUID();
    const delegated = tokenUse === "agent-delegation";
    const payload: Record<string, unknown> = {
      sub: delegated ? `user:${user!.userId}` : `agent:${agent.agentId}`,
      agentId: agent.agentId,
      scopes,
      sessionId,
      actorChain: delegated
        ? [
            { type: "user", id: user!.userId! },
            { type: "agent", id: agent.agentId },
          ]
        : [{ type: "agent", id: agent.agentId }],
      ...(delegated
        ? {
            delegatedUserId: user!.userId,
            delegatedSessionId: user!.sessionId,
            act: { sub: `agent:${agent.agentId}` },
          }
        : {}),
    };
    const accessToken = await this.keyRing.sign(payload, {
      expiresIn: this.config.tokenExpiry ?? DEFAULT_AGENT_TOKEN_EXPIRY,
      tokenUse,
    });
    const ttl = await this.tokenTtl(accessToken);

    await this.sessions.upsert(
      agent.agentId,
      accessToken,
      {
        sessionId,
        device: input.label?.slice(0, 200) || `agent:${agent.agentId}`,
        ip: input.ip?.slice(0, 100) || "unknown",
        createdAt: Date.now(),
      },
      ttl,
    );

    if (await this.isRevoked(agent.agentId)) {
      await this.sessions.revoke(agent.agentId, sessionId);
      throw new AgentIdentityError("AGENT_REVOKED", "Agent identity is revoked");
    }

    return { accessToken, sessionId, scopes, tokenUse };
  }

  private async resolveActiveAgent(
    agentId: string,
  ): Promise<RegisteredAgentIdentity> {
    const validAgentId = assertAgentId(agentId);
    if (await this.isRevoked(validAgentId)) {
      throw new AgentIdentityError("AGENT_REVOKED", "Agent identity is revoked");
    }

    const agent = await this.config.resolveAgent(validAgentId);
    if (!agent || agent.agentId !== validAgentId || agent.active === false) {
      throw new AgentIdentityError(
        "AGENT_INVALID",
        "Agent identity is unknown or inactive",
      );
    }
    normalizeScopes(agent.scopes);
    return agent;
  }

  private authorizedScopes(
    agent: RegisteredAgentIdentity,
    requested: readonly string[],
  ): string[] {
    const allowed = normalizeScopes(agent.scopes);
    const scopes = normalizeScopes(requested);
    if (!scopesAreAllowed(scopes, allowed)) {
      throw new AgentIdentityError(
        "AGENT_SCOPE_DENIED",
        "Requested agent scopes exceed the registered grant",
      );
    }
    return scopes;
  }

  private claimsAreValid(payload: AgentTokenPayload): boolean {
    try {
      assertAgentId(payload.agentId);
      assertAgentId(payload.sessionId);
      const scopes = normalizeScopes(payload.scopes);
      if (scopes.length !== payload.scopes.length) return false;

      if (payload.tokenUse === "agent") {
        return (
          payload.sub === `agent:${payload.agentId}` &&
          payload.actorChain.length === 1 &&
          payload.actorChain[0]?.type === "agent" &&
          payload.actorChain[0].id === payload.agentId &&
          !payload.delegatedUserId &&
          !payload.delegatedSessionId
        );
      }

      return (
        !!payload.delegatedUserId &&
        !!payload.delegatedSessionId &&
        payload.sub === `user:${payload.delegatedUserId}` &&
        payload.act?.sub === `agent:${payload.agentId}` &&
        payload.actorChain.length === 2 &&
        payload.actorChain[0]?.type === "user" &&
        payload.actorChain[0].id === payload.delegatedUserId &&
        payload.actorChain[1]?.type === "agent" &&
        payload.actorChain[1].id === payload.agentId
      );
    } catch {
      return false;
    }
  }

  private async authenticate(
    req: Request,
    res: Response,
    next: NextFunction,
    requiredScopes: readonly string[],
  ) {
    const authorization = req.headers.authorization;
    const token = authorization?.startsWith("Bearer ")
      ? authorization.slice("Bearer ".length).trim()
      : undefined;
    if (!token) {
      return res.status(401).json({
        error: { code: "AGENT_TOKEN_REQUIRED", message: "Agent token is required" },
      });
    }

    const agent = await this.verifyToken(token);
    if (!agent) {
      return res.status(403).json({
        error: {
          code: "AGENT_TOKEN_INVALID",
          message: "Agent token is invalid, expired, or revoked",
        },
      });
    }
    if (!scopesAreAllowed(requiredScopes, agent.scopes)) {
      return res.status(403).json({
        error: {
          code: "AGENT_SCOPE_REQUIRED",
          message: "Agent token does not grant every required scope",
        },
      });
    }

    (req as AgentAuthenticatedRequest).agent = agent;
    return next();
  }

  private async isRevoked(agentId: string): Promise<boolean> {
    return (await this.redis.exists!(this.revokedKey(agentId))) === 1;
  }

  private revokedKey(agentId: string): string {
    return `agent-revoked:${agentId}`;
  }

  private async tokenTtl(token: string): Promise<number> {
    const { decodeJwt } = await loadJose();
    const exp = decodeJwt(token).exp;
    if (!exp) {
      throw new AgentIdentityError(
        "AGENT_INVALID",
        "Agent token must contain an expiration",
      );
    }
    return Math.max(exp - Math.floor(Date.now() / 1000), 1);
  }
}
