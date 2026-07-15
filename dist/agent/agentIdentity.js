"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.AgentIdentityService = exports.AgentIdentityError = void 0;
const crypto_1 = require("crypto");
const jwk_1 = require("../auth/jwk");
const sessionStore_1 = require("../auth/sessionStore");
const DEFAULT_AGENT_TOKEN_EXPIRY = "15m";
const AGENT_SESSION_NAMESPACE = "agent-sessions";
const AGENT_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const SCOPE_PATTERN = /^[a-z][a-z0-9._/-]*(?::[a-z][a-z0-9._/-]*)+$/;
const MAX_SCOPES = 64;
class AgentIdentityError extends Error {
    constructor(code, message) {
        super(message);
        this.code = code;
        this.name = "AgentIdentityError";
    }
}
exports.AgentIdentityError = AgentIdentityError;
const assertAgentId = (agentId) => {
    if (!AGENT_ID_PATTERN.test(agentId)) {
        throw new AgentIdentityError("AGENT_INVALID", "agentId must be 1-128 letters, numbers, dots, underscores, or hyphens");
    }
    return agentId;
};
const normalizeScopes = (scopes) => {
    const normalized = [...new Set(scopes)];
    if (!normalized.length || normalized.length > MAX_SCOPES) {
        throw new AgentIdentityError("AGENT_SCOPE_DENIED", `Agent tokens require between 1 and ${MAX_SCOPES} scopes`);
    }
    if (normalized.some((scope) => scope.length > 128 || !SCOPE_PATTERN.test(scope))) {
        throw new AgentIdentityError("AGENT_SCOPE_DENIED", "Agent scopes must be at most 128 characters and use lower-case resource:action names");
    }
    return normalized.sort();
};
const scopesAreAllowed = (requested, allowed) => {
    const allowedSet = new Set(allowed);
    return requested.every((scope) => allowedSet.has(scope));
};
class AgentIdentityService {
    constructor(options) {
        this.requireAgent = async (req, res, next) => {
            return this.authenticate(req, res, next, []);
        };
        if (!options.redisClient.hget ||
            !options.redisClient.hset ||
            !options.redisClient.hdel ||
            !options.redisClient.del ||
            !options.redisClient.expire ||
            !options.redisClient.exists ||
            !options.redisClient.set) {
            throw new AgentIdentityError("AGENT_SESSION_REQUIRED", "Agent identity requires Redis hash, expiry, existence, set, and delete operations");
        }
        this.config = options.config;
        this.redis = options.redisClient;
        this.sessions = new sessionStore_1.SessionStore(options.redisClient, AGENT_SESSION_NAMESPACE);
        this.verifyHumanToken = options.verifyHumanToken;
        this.hasHumanSession = options.hasHumanSession;
        this.keyRing = new jwk_1.JwtKeyRing({
            jwk: options.jwk,
            legacySecret: options.legacySecret,
            issuer: options.issuer,
            audience: options.audience,
        });
    }
    async issueToken(input) {
        const agent = await this.resolveActiveAgent(input.agentId);
        const scopes = this.authorizedScopes(agent, input.scopes ?? agent.scopes);
        return this.issue(agent, scopes, "agent", input);
    }
    async issueDelegatedToken(input) {
        const agent = await this.resolveActiveAgent(input.agentId);
        const scopes = this.authorizedScopes(agent, input.scopes);
        const user = await this.verifyHumanToken(input.userAccessToken);
        if (!user?.userId || !user.sessionId) {
            throw new AgentIdentityError("AGENT_DELEGATION_DENIED", "Delegation requires an active human access-token session");
        }
        const sessionActive = await this.hasHumanSession(user.userId, user.sessionId);
        if (!sessionActive) {
            throw new AgentIdentityError("AGENT_DELEGATION_DENIED", "The delegating human session is no longer active");
        }
        const authorized = this.config.authorizeDelegation
            ? await this.config.authorizeDelegation({
                agent,
                user: user,
                requestedScopes: scopes,
            })
            : false;
        if (!authorized) {
            throw new AgentIdentityError("AGENT_DELEGATION_DENIED", "Agent delegation was denied by application policy");
        }
        return this.issue(agent, scopes, "agent-delegation", input, user);
    }
    async verifyToken(token) {
        try {
            const { decodeJwt } = await (0, jwk_1.loadJose)();
            const unverifiedUse = decodeJwt(token).tokenUse;
            if (unverifiedUse !== "agent" && unverifiedUse !== "agent-delegation") {
                return null;
            }
            const payload = await this.keyRing.verify(token, unverifiedUse);
            if (!this.claimsAreValid(payload))
                return null;
            if (await this.isRevoked(payload.agentId))
                return null;
            if (!(await this.sessions.tokenMatches(payload.agentId, payload.sessionId, token))) {
                return null;
            }
            const agent = await this.resolveActiveAgent(payload.agentId);
            const allowedScopes = normalizeScopes(agent.scopes);
            if (!scopesAreAllowed(payload.scopes, allowedScopes))
                return null;
            if (payload.tokenUse === "agent-delegation" &&
                !(await this.hasHumanSession(payload.delegatedUserId, payload.delegatedSessionId))) {
                return null;
            }
            return payload;
        }
        catch {
            return null;
        }
    }
    requireScopes(...scopes) {
        const requiredScopes = normalizeScopes(scopes);
        return async (req, res, next) => this.authenticate(req, res, next, requiredScopes);
    }
    async listSessions(agentId) {
        const sessions = await this.sessions.list(assertAgentId(agentId));
        return sessions.map(({ sessionId, device, ip, createdAt }) => ({
            sessionId,
            label: device,
            ip,
            createdAt,
        }));
    }
    async revokeSession(agentId, sessionId) {
        await this.sessions.revoke(assertAgentId(agentId), assertAgentId(sessionId));
    }
    async revokeAgent(agentId) {
        const validAgentId = assertAgentId(agentId);
        await this.redis.set(this.revokedKey(validAgentId), "1");
        await this.sessions.revokeAll(validAgentId);
    }
    async activateAgent(agentId) {
        await this.redis.del(this.revokedKey(assertAgentId(agentId)));
    }
    async issue(agent, scopes, tokenUse, input, user) {
        const sessionId = input.sessionId
            ? assertAgentId(input.sessionId)
            : (0, crypto_1.randomUUID)();
        const delegated = tokenUse === "agent-delegation";
        const payload = {
            sub: delegated ? `user:${user.userId}` : `agent:${agent.agentId}`,
            agentId: agent.agentId,
            scopes,
            sessionId,
            actorChain: delegated
                ? [
                    { type: "user", id: user.userId },
                    { type: "agent", id: agent.agentId },
                ]
                : [{ type: "agent", id: agent.agentId }],
            ...(delegated
                ? {
                    delegatedUserId: user.userId,
                    delegatedSessionId: user.sessionId,
                    act: { sub: `agent:${agent.agentId}` },
                }
                : {}),
        };
        const accessToken = await this.keyRing.sign(payload, {
            expiresIn: this.config.tokenExpiry ?? DEFAULT_AGENT_TOKEN_EXPIRY,
            tokenUse,
        });
        const ttl = await this.tokenTtl(accessToken);
        await this.sessions.upsert(agent.agentId, accessToken, {
            sessionId,
            device: input.label?.slice(0, 200) || `agent:${agent.agentId}`,
            ip: input.ip?.slice(0, 100) || "unknown",
            createdAt: Date.now(),
        }, ttl);
        if (await this.isRevoked(agent.agentId)) {
            await this.sessions.revoke(agent.agentId, sessionId);
            throw new AgentIdentityError("AGENT_REVOKED", "Agent identity is revoked");
        }
        return { accessToken, sessionId, scopes, tokenUse };
    }
    async resolveActiveAgent(agentId) {
        const validAgentId = assertAgentId(agentId);
        if (await this.isRevoked(validAgentId)) {
            throw new AgentIdentityError("AGENT_REVOKED", "Agent identity is revoked");
        }
        const agent = await this.config.resolveAgent(validAgentId);
        if (!agent || agent.agentId !== validAgentId || agent.active === false) {
            throw new AgentIdentityError("AGENT_INVALID", "Agent identity is unknown or inactive");
        }
        normalizeScopes(agent.scopes);
        return agent;
    }
    authorizedScopes(agent, requested) {
        const allowed = normalizeScopes(agent.scopes);
        const scopes = normalizeScopes(requested);
        if (!scopesAreAllowed(scopes, allowed)) {
            throw new AgentIdentityError("AGENT_SCOPE_DENIED", "Requested agent scopes exceed the registered grant");
        }
        return scopes;
    }
    claimsAreValid(payload) {
        try {
            assertAgentId(payload.agentId);
            assertAgentId(payload.sessionId);
            const scopes = normalizeScopes(payload.scopes);
            if (scopes.length !== payload.scopes.length)
                return false;
            if (payload.tokenUse === "agent") {
                return (payload.sub === `agent:${payload.agentId}` &&
                    payload.actorChain.length === 1 &&
                    payload.actorChain[0]?.type === "agent" &&
                    payload.actorChain[0].id === payload.agentId &&
                    !payload.delegatedUserId &&
                    !payload.delegatedSessionId);
            }
            return (!!payload.delegatedUserId &&
                !!payload.delegatedSessionId &&
                payload.sub === `user:${payload.delegatedUserId}` &&
                payload.act?.sub === `agent:${payload.agentId}` &&
                payload.actorChain.length === 2 &&
                payload.actorChain[0]?.type === "user" &&
                payload.actorChain[0].id === payload.delegatedUserId &&
                payload.actorChain[1]?.type === "agent" &&
                payload.actorChain[1].id === payload.agentId);
        }
        catch {
            return false;
        }
    }
    async authenticate(req, res, next, requiredScopes) {
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
        req.agent = agent;
        return next();
    }
    async isRevoked(agentId) {
        return (await this.redis.exists(this.revokedKey(agentId))) === 1;
    }
    revokedKey(agentId) {
        return `agent-revoked:${agentId}`;
    }
    async tokenTtl(token) {
        const { decodeJwt } = await (0, jwk_1.loadJose)();
        const exp = decodeJwt(token).exp;
        if (!exp) {
            throw new AgentIdentityError("AGENT_INVALID", "Agent token must contain an expiration");
        }
        return Math.max(exp - Math.floor(Date.now() / 1000), 1);
    }
}
exports.AgentIdentityService = AgentIdentityService;
//# sourceMappingURL=agentIdentity.js.map