"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.JWTService = void 0;
const crypto_1 = __importDefault(require("crypto"));
const jwk_1 = require("./jwk");
const sessionStore_1 = require("./sessionStore");
const requestIdentity_1 = require("./requestIdentity");
const safeString_1 = require("../utility/safeString");
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
const assertOptionalClaim = (value, label, maximumLength) => {
    if (value !== undefined &&
        (typeof value !== "string" ||
            value.length === 0 ||
            value.length > maximumLength ||
            (0, safeString_1.containsControlCharacter)(value))) {
        throw new Error(`${label} is invalid`);
    }
};
const assertOptionalClaimArray = (value, label) => {
    if (value === undefined)
        return;
    if (!Array.isArray(value) ||
        value.length > MAX_AUTHORIZATION_CLAIMS ||
        value.some((entry) => typeof entry !== "string" ||
            entry.length === 0 ||
            entry.length > MAX_AUTHORIZATION_CLAIM_LENGTH ||
            (0, safeString_1.containsControlCharacter)(entry))) {
        throw new Error(`${label} must contain at most ${MAX_AUTHORIZATION_CLAIMS} safe strings of at most ${MAX_AUTHORIZATION_CLAIM_LENGTH} characters`);
    }
};
const validateAccessClaims = (payload) => {
    assertOptionalClaim(payload.userId, "userId", MAX_IDENTITY_CLAIM_LENGTH);
    assertOptionalClaim(payload.sessionId, "sessionId", MAX_IDENTITY_CLAIM_LENGTH);
    assertOptionalClaim(payload.email, "email", 254);
    assertOptionalClaim(payload.role, "role", MAX_AUTHORIZATION_CLAIM_LENGTH);
    assertOptionalClaim(payload.scope, "scope", MAX_AUTHORIZATION_CLAIMS *
        (MAX_AUTHORIZATION_CLAIM_LENGTH + 1));
    assertOptionalClaim(payload.tenantId, "tenantId", MAX_IDENTITY_CLAIM_LENGTH);
    assertOptionalClaimArray(payload.roles, "roles");
    assertOptionalClaimArray(payload.permissions, "permissions");
    assertOptionalClaimArray(payload.scopes, "scopes");
    assertOptionalClaimArray(payload.tenantIds, "tenantIds");
};
const validateAccessPayload = (payload) => {
    validateAccessClaims(payload);
    let serialized;
    try {
        serialized = JSON.stringify(payload);
    }
    catch {
        throw new Error("Access token payload must be JSON serializable");
    }
    if (Buffer.byteLength(serialized, "utf8") > MAX_ACCESS_PAYLOAD_BYTES) {
        throw new Error(`Access token payload must not exceed ${MAX_ACCESS_PAYLOAD_BYTES} bytes`);
    }
};
class JWTService {
    constructor(options) {
        this.authenticateJWT = async (req, res, next) => {
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
                const sessionIsValid = await this.sessionIsValid(decoded, token, this.resolveRequestContext?.(req));
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
            req.user = decoded;
            (0, requestIdentity_1.markAuthenik8Authenticated)(req);
            return next();
        };
        if (options.allowCookieAuth !== undefined &&
            typeof options.allowCookieAuth !== "boolean") {
            throw new Error("allowCookieAuth must be a boolean");
        }
        this.expirySeconds = (0, jwk_1.normalizeTokenLifetime)(options.expiry ?? ACCESS_TOKEN_FALLBACK_EXPIRY, "jwtExpiry", 60, MAX_ACCESS_TOKEN_TTL_SECONDS);
        this.redisClient = options.redisClient;
        this.onGuestToken = options.onGuestToken;
        this.allowCookieAuth = options.allowCookieAuth ?? false;
        this.audit = options.audit;
        this.risk = options.risk;
        this.resolveRequestContext = options.resolveRequestContext;
        this.sessionStore = new sessionStore_1.SessionStore(options.redisClient, options.sessionKeyPrefix ?? "sessions");
        this.keyRing = new jwk_1.JwtKeyRing({
            jwk: options.jwk,
            legacySecret: options.jwtSecret,
            issuer: options.issuer,
            audience: options.audience,
        });
    }
    get issuer() {
        return this.keyRing.issuer;
    }
    get audience() {
        return this.keyRing.audience;
    }
    getJwks() {
        return this.keyRing.getJwks();
    }
    async listSessions(userId) {
        return this.sessionStore.list(userId);
    }
    async revokeAllSessions(userId) {
        await this.sessionStore.revokeAll(userId);
        await this.audit?.emit({
            type: "session.revoked_all",
            severity: "warning",
            outcome: "success",
            actor: { type: "system" },
            subject: { type: "user", id: userId },
        });
    }
    async revokeSession(userId, sessionId) {
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
    async signToken(payload, meta) {
        validateAccessPayload(payload);
        const sessionId = payload.sessionId ?? crypto_1.default.randomUUID();
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
        }
        catch (error) {
            if (payload.userId) {
                await this.sessionStore.revoke(payload.userId, sessionId);
            }
            throw error;
        }
        return token;
    }
    async guestToken() {
        const payload = {
            type: "guest",
            id: crypto_1.default.randomUUID(),
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
    async verifyToken(token) {
        try {
            const payload = await this.keyRing.verify(token, "access");
            validateAccessClaims(payload);
            return payload;
        }
        catch {
            return null;
        }
    }
    async verifyActiveToken(token) {
        const decoded = await this.verifyToken(token);
        if (!decoded)
            return null;
        if (!this.redisClient)
            return decoded;
        return (await this.sessionIsValid(decoded, token)) ? decoded : null;
    }
    async hasActiveSession(userId, sessionId) {
        if (!this.redisClient)
            return false;
        const session = await this.sessionStore.get(userId, sessionId);
        if (!session)
            return false;
        return !(await this.risk?.isQuarantined({
            kind: "human",
            id: userId,
            sessionId,
        }));
    }
    async verifyGuestToken(token) {
        try {
            return await this.keyRing.verify(token, "guest");
        }
        catch {
            return null;
        }
    }
    tokenFromRequest(req) {
        const authHeader = req.headers.authorization;
        const match = typeof authHeader === "string" && authHeader.length <= 16 * 1024 + 16
            ? /^Bearer ([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)$/i.exec(authHeader)
            : null;
        const bearerToken = match?.[1];
        const rawCookieToken = this.allowCookieAuth ? req.cookies?.token : undefined;
        const cookieToken = typeof rawCookieToken === "string" &&
            rawCookieToken.length <= 16 * 1024
            ? rawCookieToken
            : undefined;
        if (bearerToken && cookieToken && bearerToken !== cookieToken) {
            return undefined;
        }
        return bearerToken ?? cookieToken;
    }
    async sessionIsValid(decoded, token, observed) {
        if (!decoded.userId || !decoded.sessionId)
            return false;
        const session = await this.sessionStore.get(decoded.userId, decoded.sessionId);
        if (!session || !(0, sessionStore_1.sessionTokenMatches)(session, token))
            return false;
        const principal = {
            kind: "human",
            id: decoded.userId,
            sessionId: decoded.sessionId,
        };
        if (await this.risk?.isQuarantined(principal))
            return false;
        if (observed && this.risk) {
            const state = await this.risk.assessContext(principal, { ip: session.ip, device: session.device }, observed);
            if (state.status === "quarantined")
                return false;
        }
        return true;
    }
    async persistSessionToken(payload, token, metadata) {
        if (!this.redisClient || !payload.userId)
            return;
        await this.sessionStore.updateToken(payload.userId, metadata.sessionId, token, this.expirySeconds, metadata);
    }
    correlationId(req) {
        const value = req.headers["x-request-id"];
        return typeof value === "string" &&
            value.length > 0 &&
            value.length <= 128 &&
            !(0, safeString_1.containsControlCharacter)(value)
            ? value
            : undefined;
    }
}
exports.JWTService = JWTService;
//# sourceMappingURL=jwtAuth.js.map