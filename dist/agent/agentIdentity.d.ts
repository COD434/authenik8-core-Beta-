import type { NextFunction, Request, Response } from "express";
import type { Authenik8JwkConfig } from "../auth/jwk";
import type { JwtPayload } from "../auth/jwtAuth";
import type { AgentIdentityApi, AgentIdentityConfig, AgentSessionMetadata, AgentTokenPayload, AgentTokenResult, IssueAgentTokenInput, IssueDelegatedAgentTokenInput } from "./types";
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
export declare class AgentIdentityError extends Error {
    readonly code: "AGENT_INVALID" | "AGENT_REVOKED" | "AGENT_SCOPE_DENIED" | "AGENT_DELEGATION_DENIED" | "AGENT_SESSION_REQUIRED";
    constructor(code: "AGENT_INVALID" | "AGENT_REVOKED" | "AGENT_SCOPE_DENIED" | "AGENT_DELEGATION_DENIED" | "AGENT_SESSION_REQUIRED", message: string);
}
export declare class AgentIdentityService implements AgentIdentityApi {
    private readonly config;
    private readonly redis;
    private readonly keyRing;
    private readonly sessions;
    private readonly verifyHumanToken;
    private readonly hasHumanSession;
    constructor(options: AgentIdentityServiceOptions);
    issueToken(input: IssueAgentTokenInput): Promise<AgentTokenResult>;
    issueDelegatedToken(input: IssueDelegatedAgentTokenInput): Promise<AgentTokenResult>;
    verifyToken(token: string): Promise<AgentTokenPayload | null>;
    requireAgent: (req: Request, res: Response, next: NextFunction) => Promise<void | Response<any, Record<string, any>>>;
    requireScopes(...scopes: string[]): (req: Request, res: Response, next: NextFunction) => Promise<void | Response<any, Record<string, any>>>;
    listSessions(agentId: string): Promise<AgentSessionMetadata[]>;
    revokeSession(agentId: string, sessionId: string): Promise<void>;
    revokeAgent(agentId: string): Promise<void>;
    activateAgent(agentId: string): Promise<void>;
    private issue;
    private resolveActiveAgent;
    private authorizedScopes;
    private claimsAreValid;
    private authenticate;
    private isRevoked;
    private revokedKey;
    private tokenTtl;
}
export {};
//# sourceMappingURL=agentIdentity.d.ts.map