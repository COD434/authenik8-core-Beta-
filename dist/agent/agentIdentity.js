"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.AgentIdentityService = exports.AgentIdentityError = void 0;
const crypto_1 = require("crypto");
const jwk_1 = require("../auth/jwk");
const sessionStore_1 = require("../auth/sessionStore");
const keyNamespace_1 = require("../redis/keyNamespace");
const safeString_1 = require("../utility/safeString");
const DEFAULT_AGENT_TOKEN_EXPIRY = "15m";
const MAX_AGENT_TOKEN_TTL_SECONDS = 60 * 60;
const AGENT_SESSION_NAMESPACE = "agent-sessions";
const AGENT_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const SCOPE_PATTERN = /^[a-z][a-z0-9._/-]*(?::[a-z][a-z0-9._/-]*)+$/;
const MAX_SCOPES = 64;
const MAX_DELEGATED_ID_LENGTH = 256;
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
const assertDelegatedIdentity = (value, label) => {
    if (typeof value !== "string" ||
        value.length === 0 ||
        value.length > MAX_DELEGATED_ID_LENGTH ||
        (0, safeString_1.containsControlCharacter)(value)) {
        throw new AgentIdentityError("AGENT_DELEGATION_DENIED", `${label} is invalid`);
    }
    return value;
};
const optionalSessionMetadata = (value, label, maximumLength) => {
    if (value === undefined)
        return undefined;
    if (typeof value !== "string" ||
        value.length === 0 ||
        value.length > maximumLength ||
        (0, safeString_1.containsControlCharacter)(value)) {
        throw new AgentIdentityError("AGENT_INVALID", `${label} is invalid`);
    }
    return value;
};
class AgentIdentityService {
    constructor(options) {
        this.requireAgent = async (req, res, next) => {
            return this.authenticate(req, res, next, []);
        };
        if (!options.config ||
            typeof options.config.resolveAgent !== "function" ||
            (options.config.authorizeDelegation !== undefined &&
                typeof options.config.authorizeDelegation !== "function")) {
            throw new AgentIdentityError("AGENT_INVALID", "Agent identity requires valid registry and delegation callbacks");
        }
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
        this.tokenExpirySeconds = (0, jwk_1.normalizeTokenLifetime)(options.config.tokenExpiry ?? DEFAULT_AGENT_TOKEN_EXPIRY, "agent.tokenExpiry", 60, MAX_AGENT_TOKEN_TTL_SECONDS);
        this.redis = options.redisClient;
        this.keyPrefix = options.keyPrefix
            ? (0, keyNamespace_1.validateRedisKeyPrefix)(options.keyPrefix)
            : "";
        this.sessions = new sessionStore_1.SessionStore(options.redisClient, this.scoped(AGENT_SESSION_NAMESPACE));
        this.verifyHumanToken = options.verifyHumanToken;
        this.hasHumanSession = options.hasHumanSession;
        this.audit = options.audit;
        this.risk = options.risk;
        this.keyRing = new jwk_1.JwtKeyRing({
            jwk: options.jwk,
            legacySecret: options.legacySecret,
            issuer: options.issuer,
            audience: options.audience,
        });
    }
    async issueToken(input) {
        try {
            const agent = await this.resolveActiveAgent(input.agentId);
            const scopes = this.authorizedScopes(agent, input.scopes ?? agent.scopes);
            return await this.issue(agent, scopes, "agent", input);
        }
        catch (error) {
            await this.auditAgentRejection(input.agentId, error);
            throw error;
        }
    }
    async issueDelegatedToken(input) {
        try {
            const agent = await this.resolveActiveAgent(input.agentId);
            const scopes = this.authorizedScopes(agent, input.scopes);
            const user = await this.verifyHumanToken(input.userAccessToken);
            if (!user?.userId || !user.sessionId) {
                throw new AgentIdentityError("AGENT_DELEGATION_DENIED", "Delegation requires an active human access-token session");
            }
            const delegatedUserId = assertDelegatedIdentity(user.userId, "Delegated userId");
            const delegatedSessionId = assertDelegatedIdentity(user.sessionId, "Delegated sessionId");
            const verifiedUser = Object.freeze({
                ...user,
                userId: delegatedUserId,
                sessionId: delegatedSessionId,
            });
            const sessionActive = await this.hasHumanSession(delegatedUserId, delegatedSessionId);
            if (!sessionActive) {
                throw new AgentIdentityError("AGENT_DELEGATION_DENIED", "The delegating human session is no longer active");
            }
            const authorized = this.config.authorizeDelegation
                ? await this.config.authorizeDelegation({
                    agent,
                    user: verifiedUser,
                    requestedScopes: Object.freeze([...scopes]),
                })
                : false;
            if (authorized !== true) {
                throw new AgentIdentityError("AGENT_DELEGATION_DENIED", "Agent delegation was denied by application policy");
            }
            return await this.issue(agent, scopes, "agent-delegation", input, verifiedUser);
        }
        catch (error) {
            await this.auditAgentRejection(input.agentId, error);
            throw error;
        }
    }
    async verifyToken(token) {
        try {
            const unverifiedUse = (await (0, jwk_1.decodeBoundedJwt)(token)).tokenUse;
            if (unverifiedUse !== "agent" && unverifiedUse !== "agent-delegation") {
                return null;
            }
            const payload = await this.keyRing.verify(token, unverifiedUse);
            if (!this.claimsAreValid(payload))
                return null;
            if (await this.risk?.isQuarantined(this.riskPrincipal(payload))) {
                return this.rejectVerifiedAgent(payload, "quarantined_session");
            }
            if (await this.isRevoked(payload.agentId)) {
                return this.rejectVerifiedAgent(payload, "revoked_agent");
            }
            if (!(await this.sessions.tokenMatches(payload.agentId, payload.sessionId, token))) {
                return this.rejectVerifiedAgent(payload, "session_token_mismatch");
            }
            const agent = await this.resolveActiveAgent(payload.agentId);
            const allowedScopes = normalizeScopes(agent.scopes);
            if (!scopesAreAllowed(payload.scopes, allowedScopes)) {
                return this.rejectVerifiedAgent(payload, "registry_scope_mismatch");
            }
            if (payload.tokenUse === "agent-delegation" &&
                !(await this.hasHumanSession(payload.delegatedUserId, payload.delegatedSessionId))) {
                return this.rejectVerifiedAgent(payload, "delegating_session_inactive");
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
        await this.audit?.emit({
            type: "agent.revoked",
            severity: "critical",
            outcome: "success",
            actor: { type: "system" },
            subject: { type: "agent", id: validAgentId },
        });
    }
    async activateAgent(agentId) {
        const validAgentId = assertAgentId(agentId);
        await this.redis.del(this.revokedKey(validAgentId));
        await this.audit?.emit({
            type: "agent.activated",
            severity: "warning",
            outcome: "success",
            actor: { type: "system" },
            subject: { type: "agent", id: validAgentId },
        });
    }
    async issue(agent, scopes, tokenUse, input, user) {
        const sessionId = input.sessionId
            ? assertAgentId(input.sessionId)
            : (0, crypto_1.randomUUID)();
        const label = optionalSessionMetadata(input.label, "Agent label", 200);
        const ip = optionalSessionMetadata(input.ip, "Agent IP", 100);
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
            expiresInSeconds: this.tokenExpirySeconds,
            tokenUse,
        });
        await this.sessions.upsert(agent.agentId, accessToken, {
            sessionId,
            device: label ?? `agent:${agent.agentId}`,
            ip: ip ?? "unknown",
            createdAt: Date.now(),
        }, this.tokenExpirySeconds);
        if (await this.isRevoked(agent.agentId)) {
            await this.sessions.revoke(agent.agentId, sessionId);
            throw new AgentIdentityError("AGENT_REVOKED", "Agent identity is revoked");
        }
        try {
            await this.audit?.emit({
                type: "agent_token.issued",
                severity: "info",
                outcome: "success",
                actor: { type: "system" },
                subject: { type: "agent", id: agent.agentId },
                sessionId,
                metadata: {
                    tokenUse,
                    scopes,
                    ...(delegated && user?.userId
                        ? { delegatedUserId: user.userId }
                        : {}),
                },
            });
        }
        catch (error) {
            await this.sessions.revoke(agent.agentId, sessionId);
            throw error;
        }
        return { accessToken, sessionId, scopes, tokenUse };
    }
    async resolveActiveAgent(agentId) {
        const validAgentId = assertAgentId(agentId);
        if (await this.isRevoked(validAgentId)) {
            throw new AgentIdentityError("AGENT_REVOKED", "Agent identity is revoked");
        }
        const agent = await this.config.resolveAgent(validAgentId);
        if (!agent ||
            agent.agentId !== validAgentId ||
            (agent.active !== undefined && typeof agent.active !== "boolean") ||
            agent.active === false) {
            throw new AgentIdentityError("AGENT_INVALID", "Agent identity is unknown or inactive");
        }
        const scopes = Object.freeze(normalizeScopes(agent.scopes));
        return Object.freeze({
            agentId: validAgentId,
            scopes,
            ...(agent.active !== undefined ? { active: agent.active } : {}),
        });
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
            const delegatedUserId = assertDelegatedIdentity(payload.delegatedUserId, "Delegated userId");
            const delegatedSessionId = assertDelegatedIdentity(payload.delegatedSessionId, "Delegated sessionId");
            return (payload.sub === `user:${delegatedUserId}` &&
                payload.act?.sub === `agent:${payload.agentId}` &&
                payload.actorChain.length === 2 &&
                payload.actorChain[0]?.type === "user" &&
                payload.actorChain[0].id === delegatedUserId &&
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
            await this.risk?.report({
                type: "suspicious_agent_activity",
                principal: this.riskPrincipal(agent),
                metadata: { reason: "route_scope_denied" },
            });
            await this.audit?.emit({
                type: "agent_token.rejected",
                severity: "warning",
                outcome: "denied",
                actor: { type: "agent", id: agent.agentId },
                sessionId: agent.sessionId,
                metadata: { reason: "route_scope_denied", requiredScopes },
            });
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
        return this.scoped("agent-revoked", agentId);
    }
    scoped(...parts) {
        return [this.keyPrefix, ...parts].filter(Boolean).join(":");
    }
    riskPrincipal(payload) {
        return {
            kind: "agent",
            id: payload.agentId,
            sessionId: payload.sessionId,
        };
    }
    async rejectVerifiedAgent(payload, reason) {
        await this.risk?.report({
            type: "suspicious_agent_activity",
            principal: this.riskPrincipal(payload),
            metadata: { reason },
        });
        await this.audit?.emit({
            type: "agent_token.rejected",
            severity: "warning",
            outcome: "denied",
            actor: { type: "agent", id: payload.agentId },
            sessionId: payload.sessionId,
            metadata: { reason },
        });
        return null;
    }
    async auditAgentRejection(agentId, error) {
        let actor = { type: "unknown" };
        try {
            actor = { type: "agent", id: assertAgentId(agentId) };
        }
        catch {
            // Invalid caller-controlled identifiers must not poison audit delivery.
        }
        await this.audit?.emit({
            type: "agent_token.rejected",
            severity: "warning",
            outcome: "denied",
            actor,
            metadata: {
                reason: error instanceof AgentIdentityError ? error.code : "issuance_failed",
            },
        });
    }
}
exports.AgentIdentityService = AgentIdentityService;
//# sourceMappingURL=agentIdentity.js.map