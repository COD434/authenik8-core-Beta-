"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.JWTService = void 0;
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const crypto_1 = __importDefault(require("crypto"));
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
            try {
                const decoded = jsonwebtoken_1.default.verify(token, this.jwtSecret);
                if (this.redisClient) {
                    const sessionIsValid = await this.sessionIsValid(decoded, token);
                    if (!sessionIsValid) {
                        return res.status(403).json(INVALID_SESSION_RESPONSE);
                    }
                }
                req.user = decoded;
                return next();
            }
            catch {
                return res
                    .status(403)
                    .json({ success: false, message: "invalid or expired token" });
            }
        };
        this.jwtSecret = options.jwtSecret;
        this.expiry = options.expiry;
        this.redisClient = options.redisClient;
        this.onGuestToken = options.onGuestToken;
        this.allowCookieAuth = options.allowCookieAuth ?? false;
        this.sessionStore = new sessionStore_1.SessionStore(options.redisClient);
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
        const token = jsonwebtoken_1.default.sign(fullPayload, this.jwtSecret, {
            expiresIn: this.expiry || ACCESS_TOKEN_FALLBACK_EXPIRY,
        });
        await this.persistSessionToken(fullPayload, token, {
            sessionId,
            device: meta?.device || "unknown",
            ip: meta?.ip || "unknown",
            createdAt: Date.now(),
        });
        return token;
    }
    guestToken() {
        const payload = {
            type: "guest",
            id: crypto_1.default.randomUUID(),
            createdAt: Date.now(),
        };
        if (this.onGuestToken) {
            this.onGuestToken();
        }
        return jsonwebtoken_1.default.sign(payload, this.jwtSecret, { expiresIn: this.expiry });
    }
    verifyToken(token) {
        try {
            return jsonwebtoken_1.default.verify(token, this.jwtSecret);
        }
        catch {
            return null;
        }
    }
    tokenFromRequest(req) {
        const authHeader = req.headers.authorization;
        const bearerToken = authHeader?.startsWith("Bearer ")
            ? authHeader.split(" ")[1]
            : undefined;
        const cookieToken = this.allowCookieAuth ? req.cookies?.token : undefined;
        return bearerToken || cookieToken;
    }
    async sessionIsValid(decoded, token) {
        if (!decoded.userId || !decoded.sessionId) {
            return false;
        }
        return this.sessionStore.tokenMatches(decoded.userId, decoded.sessionId, token);
    }
    async persistSessionToken(payload, token, metadata) {
        if (!this.redisClient || !payload.userId)
            return;
        try {
            const ttl = this.tokenTtlSeconds(token);
            await this.sessionStore.upsert(payload.userId, token, metadata, ttl);
        }
        catch {
            // Session persistence must not make token signing fail.
        }
    }
    tokenTtlSeconds(token) {
        const decoded = jsonwebtoken_1.default.decode(token);
        const now = Math.floor(Date.now() / 1000);
        return decoded?.exp
            ? Math.max(decoded.exp - now, 1)
            : SESSION_TTL_FALLBACK_SECONDS;
    }
}
exports.JWTService = JWTService;
//# sourceMappingURL=jwtAuth.js.map