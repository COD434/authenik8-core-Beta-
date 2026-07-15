"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.JWTService = void 0;
const crypto_1 = __importDefault(require("crypto"));
const jwk_1 = require("./jwk");
const sessionStore_1 = require("./sessionStore");
const ACCESS_TOKEN_FALLBACK_EXPIRY = "1h";
const SESSION_TTL_FALLBACK_SECONDS = 3600;
const INVALID_SESSION_RESPONSE = {
    success: false,
    message: "invalid session",
    errors: [],
};
class JWTService {
    constructor(options) {
        this.authenticateJWT = async (req, res, next) => {
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
            req.user = decoded;
            return next();
        };
        this.expiry = options.expiry ?? ACCESS_TOKEN_FALLBACK_EXPIRY;
        this.redisClient = options.redisClient;
        this.onGuestToken = options.onGuestToken;
        this.allowCookieAuth = options.allowCookieAuth ?? false;
        this.sessionStore = new sessionStore_1.SessionStore(options.redisClient);
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
    }
    async revokeSession(userId, sessionId) {
        await this.sessionStore.revoke(userId, sessionId);
    }
    async signToken(payload, meta) {
        const sessionId = payload.sessionId ?? crypto_1.default.randomUUID();
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
    async guestToken() {
        const payload = {
            type: "guest",
            id: crypto_1.default.randomUUID(),
            createdAt: Date.now(),
        };
        this.onGuestToken?.();
        return this.keyRing.sign(payload, {
            expiresIn: this.expiry,
            tokenUse: "guest",
        });
    }
    async verifyToken(token) {
        try {
            return await this.keyRing.verify(token, "access");
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
        return !!(await this.sessionStore.get(userId, sessionId));
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
        const bearerToken = authHeader?.startsWith("Bearer ")
            ? authHeader.slice("Bearer ".length).trim()
            : undefined;
        const cookieToken = this.allowCookieAuth ? req.cookies?.token : undefined;
        return bearerToken || cookieToken;
    }
    async sessionIsValid(decoded, token) {
        if (!decoded.userId || !decoded.sessionId)
            return false;
        return this.sessionStore.tokenMatches(decoded.userId, decoded.sessionId, token);
    }
    async persistSessionToken(payload, token, metadata) {
        if (!this.redisClient || !payload.userId)
            return;
        try {
            const { decodeJwt } = await (0, jwk_1.loadJose)();
            const decoded = decodeJwt(token);
            const now = Math.floor(Date.now() / 1000);
            const ttl = decoded.exp
                ? Math.max(decoded.exp - now, 1)
                : SESSION_TTL_FALLBACK_SECONDS;
            await this.sessionStore.upsert(payload.userId, token, metadata, ttl);
        }
        catch {
            // Session persistence must not make token signing fail.
        }
    }
}
exports.JWTService = JWTService;
//# sourceMappingURL=jwtAuth.js.map