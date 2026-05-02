"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.requireAdmin = void 0;
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const requireAdmin = (options) => {
    return (req, res, next) => {
        const authHeader = req.headers.authorization;
        const cookieToken = req.cookies?.token;
        let token;
        if (authHeader && authHeader.startsWith("Bearer")) {
            token = authHeader.split(" ")[1];
        }
        if (!token && cookieToken) {
            token = cookieToken;
        }
        if (!token) {
            return res.status(401).json({ error: "Unauthorized:No token provided" });
        }
        try {
            const decoded = jsonwebtoken_1.default.verify(token, options.jwtSecret);
            if (decoded.role !== "admin") {
                return res.status(403).json({ error: "Forbidden: Admin only" });
            }
            if (options.redisclient) {
                req.adminActions = {
                    listSessions: async (userId) => {
                        const sessions = await options.redisclient.hgetall(`sessions:${userId}`);
                        return Object.values(sessions || {}).map((s) => {
                            const { token, ...meta } = JSON.parse(s);
                            return meta;
                        });
                    },
                    revokeSession: async (userId, sessionId) => {
                        await options.redisclient.hdel(`sessions:${userId}`, sessionId);
                    },
                    revokeAllSessions: async (userId) => {
                        await options.redisclient.del(`sessions:${userId}`);
                    },
                };
            }
            req.user = decoded;
            return next();
        }
        catch {
            return res.status(401).json({ error: "Invalid or expired token" });
        }
    };
};
exports.requireAdmin = requireAdmin;
//# sourceMappingURL=adminService.js.map