import type { Request, RequestHandler } from "express";
import type { JWTPayload } from "jose" with { "resolution-mode": "import" };
import type { JwtPayload } from "../auth/jwtAuth";

export type AgentTokenUse = "agent" | "agent-delegation";

export interface IdentityActor {
  type: "user" | "agent";
  id: string;
}

export interface RegisteredAgentIdentity {
  agentId: string;
  scopes: readonly string[];
  active?: boolean;
}

export interface AgentDelegationRequest {
  agent: RegisteredAgentIdentity;
  user: JwtPayload & { userId: string; sessionId: string };
  requestedScopes: readonly string[];
}

export interface AgentIdentityConfig {
  /** Agent access tokens should remain short-lived. Defaults to 15 minutes. */
  tokenExpiry?: string | number;
  /** Resolve the application's source of truth for registered agent identities. */
  resolveAgent: (
    agentId: string,
  ) => RegisteredAgentIdentity | null | Promise<RegisteredAgentIdentity | null>;
  /** Delegation fails closed when this policy is omitted or returns false. */
  authorizeDelegation?: (
    request: AgentDelegationRequest,
  ) => boolean | Promise<boolean>;
}

export interface AgentSessionInput {
  sessionId?: string;
  label?: string;
  ip?: string;
}

export interface IssueAgentTokenInput extends AgentSessionInput {
  agentId: string;
  /** Defaults to all scopes currently granted by the agent registry. */
  scopes?: readonly string[];
}

export interface IssueDelegatedAgentTokenInput extends AgentSessionInput {
  agentId: string;
  userAccessToken: string;
  scopes: readonly string[];
}

export interface AgentTokenPayload extends JWTPayload {
  agentId: string;
  scopes: string[];
  sessionId: string;
  tokenUse: AgentTokenUse;
  actorChain: IdentityActor[];
  delegatedUserId?: string;
  delegatedSessionId?: string;
  act?: { sub: string };
}

export interface AgentTokenResult {
  accessToken: string;
  sessionId: string;
  scopes: string[];
  tokenUse: AgentTokenUse;
}

export type AgentAuthenticatedRequest = Request & { agent: AgentTokenPayload };

export interface AgentSessionMetadata {
  sessionId: string;
  label: string;
  ip: string;
  createdAt: number;
}

export interface AgentIdentityApi {
  issueToken(input: IssueAgentTokenInput): Promise<AgentTokenResult>;
  issueDelegatedToken(
    input: IssueDelegatedAgentTokenInput,
  ): Promise<AgentTokenResult>;
  verifyToken(token: string): Promise<AgentTokenPayload | null>;
  requireAgent: RequestHandler;
  requireScopes(...scopes: string[]): RequestHandler;
  listSessions(agentId: string): Promise<AgentSessionMetadata[]>;
  revokeSession(agentId: string, sessionId: string): Promise<void>;
  revokeAgent(agentId: string): Promise<void>;
  activateAgent(agentId: string): Promise<void>;
}
