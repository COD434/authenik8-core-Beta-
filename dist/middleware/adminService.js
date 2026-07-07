"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.requireAdmin = void 0;
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const sessionStore_1 = require("../auth/sessionStore");
const ADMIN_ONLY_ERROR = { error: "Forbidden: Admin only" };
const INVALID_ADMIN_SESSION_ERROR = {
    error: "Forbidden: invalid admin session",
};
const requireAdmin = (options) => {
    const sessionStore = new sessionStore_1.SessionStore(options.store);
    return async (req, res, next) => {
        const token = tokenFromRequest(req, options.allowCookieAuth ?? false);
        if (!token) {
            return res.status(401).json({ error: "Unauthorized:No token provided" });
        }
        try {
            const decoded = jsonwebtoken_1.default.verify(token, options.jwtSecret);
            if (decoded.role !== "admin") {
                return res.status(403).json(ADMIN_ONLY_ERROR);
            }
            if (options.store) {
                const sessionIsValid = await adminSessionIsValid(sessionStore, decoded, token);
                if (!sessionIsValid) {
                    return res.status(403).json(INVALID_ADMIN_SESSION_ERROR);
                }
                attachAdminActions(req, sessionStore);
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
const tokenFromRequest = (req, allowCookieAuth) => {
    const authHeader = req.headers.authorization;
    const bearerToken = authHeader?.startsWith("Bearer ")
        ? authHeader.split(" ")[1]
        : undefined;
    const cookieToken = allowCookieAuth ? req.cookies?.token : undefined;
    return bearerToken || cookieToken;
};
const adminSessionIsValid = async (sessionStore, decoded, token) => {
    if (!decoded.userId || !decoded.sessionId) {
        return false;
    }
    return sessionStore.tokenMatches(decoded.userId, decoded.sessionId, token);
};
const attachAdminActions = (req, sessionStore) => {
    req.adminActions = {
        listSessions: (userId) => sessionStore.list(userId),
        revokeSession: (userId, sessionId) => sessionStore.revoke(userId, sessionId),
        revokeAllSessions: (userId) => sessionStore.revokeAll(userId),
    };
};
//# sourceMappingURL=adminService.js.map