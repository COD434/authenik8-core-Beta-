"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.requireAdmin = void 0;
const jwtAuth_1 = require("../auth/jwtAuth");
const sessionStore_1 = require("../auth/sessionStore");
const ADMIN_ONLY_ERROR = { error: "Forbidden: Admin only" };
const requireAdmin = (options) => {
    const sessionStore = new sessionStore_1.SessionStore(options.store);
    const requireAuth = options.requireAuth ??
        new jwtAuth_1.JWTService({
            jwtSecret: options.jwtSecret,
            redisClient: options.store,
            allowCookieAuth: options.allowCookieAuth,
        }).authenticateJWT;
    return async (req, res, next) => {
        return requireAuth(req, res, () => {
            const user = req.user;
            if (user?.role !== "admin") {
                return res.status(403).json(ADMIN_ONLY_ERROR);
            }
            if (options.store || options.listSessions)
                attachAdminActions(req, sessionStore, options);
            return next();
        });
    };
};
exports.requireAdmin = requireAdmin;
const attachAdminActions = (req, sessionStore, options) => {
    req.adminActions = {
        listSessions: (userId) => options.listSessions?.(userId) ?? sessionStore.list(userId),
        revokeSession: (userId, sessionId) => options.revokeSession?.(userId, sessionId) ?? sessionStore.revoke(userId, sessionId),
        revokeAllSessions: (userId) => options.revokeAllSessions?.(userId) ?? sessionStore.revokeAll(userId),
    };
};
//# sourceMappingURL=adminService.js.map