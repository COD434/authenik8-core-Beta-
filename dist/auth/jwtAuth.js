"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.JWTService = void 0;
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const crypto_1 = __importDefault(require("crypto"));
class JWTService {
    constructor(options) {
        this.authenticateJWT = async (req, res, next) => {
            const authHeader = req.headers.authorization;
            const token = req.cookies?.token || (authHeader?.startsWith("Bearer ") ? authHeader.split(" ")[1] : null);
            if (!token) {
                return res.status(401).json({ message: "Unauthorized" });
            }
            try {
                const decoded = jsonwebtoken_1.default.verify(token, this.jwtSecret);
                console.log("Redis Client exists?", !!this.redisclient);
                console.log("Decoded UserID:", decoded.userId);
                console.log("Full key:", `sessions:${decoded.userId}`);
                if (this.redisclient && decoded.userId) {
                    const sessions = await this.redisclient.hgetall(`sessions:${decoded.userId}`);
                    console.log("HGETALL called!");
                    const match = Object.values(sessions || {}).find((s) => JSON.parse(s).token === token);
                    if (!match) {
                        return res.status(403).json({ success: false, message: "invalid session", errors: [] });
                    }
                }
                req.user = decoded;
                return next();
            }
            catch {
                return res.status(403).json({ success: false, message: "invalid or expired token" });
            }
        };
        this.jwtSecret = options.jwtSecret;
        this.expiry = options.expiry;
        this.redisclient = options.redisClient;
        this.onGuestToken = options.onGuestToken;
    }
    async listSessions(userId) {
        if (!this.redisclient)
            return [];
        const sessions = await this.redisclient.hgetall(`sessions:${userId}`);
        return Object.values(sessions || {}).map((s) => {
            const { token, ...meta } = JSON.parse(s);
            return meta;
        });
    }
    async revokeAllSessions(userId) {
        if (!this.redisclient)
            return;
        await this.redisclient.del(`sessions:${userId}`);
    }
    async revokeSession(userId, sessionId) {
        await this.redisclient.hdel(`sessions:${userId}`, sessionId);
    }
    async persistSessionToken(payload, token, meta) {
        if (!this.redisclient)
            return;
        const userId = payload.userId;
        if (!userId)
            return;
        try {
            const decoded = jsonwebtoken_1.default.decode(token);
            const now = Math.floor(Date.now() / 1000);
            const ttl = decoded?.exp ? Math.max(decoded.exp - now, 1) : 3600;
            await this.redisclient.hset(`sessions:${userId}`, meta.sessionId, JSON.stringify({ token, ...meta }));
            await this.redisclient.expire(`sessions:${userId}`, ttl);
        }
        catch (err) {
            console.error('Failed to persist session token:', err);
        }
    }
    async signToken(payload, meta) {
        const sessionId = crypto_1.default.randomUUID();
        const fullPayload = { ...payload, sessionId };
        const token = jsonwebtoken_1.default.sign(fullPayload, this.jwtSecret, {
            expiresIn: this.expiry || "1h"
        });
        this.persistSessionToken(payload, token, {
            sessionId,
            device: meta?.device || "unknown",
            ip: meta?.ip || "unknown",
            createdAt: Date.now()
        });
        return token;
    }
    ;
    guestToken() {
        const payload = {
            type: "guest",
            id: crypto_1.default.randomUUID(),
            createdAt: Date.now()
        };
        if (this.onGuestToken)
            this.onGuestToken();
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
}
exports.JWTService = JWTService;
//# sourceMappingURL=jwtAuth.js.map