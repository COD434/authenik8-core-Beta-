"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.requireAdmin = void 0;
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const requireAdmin = (config) => {
    return (req, res, next) => {
        var _a;
        const authHeader = req.headers.authorization || req.cookies.token;
        const cookieToken = (_a = req.cookies) === null || _a === void 0 ? void 0 : _a.token;
        const rawToken = authHeader || cookieToken;
        if (!rawToken) {
            return res.status(401).json({ error: "Unauthorized:No token provided" });
        }
        const token = typeof rawToken === "string" && rawToken.startsWith("Bearer ") ? rawToken.split(" ")[1] : rawToken;
        try {
            const decoded = jsonwebtoken_1.default.verify(token, process.env.JWT_SECRET);
            if (decoded.role !== "ADMIN") {
                res.status(403).json({ error: "Forbidden: Admin only" });
            }
            next();
        }
        catch (error) {
            res.status(401).json({ error: "Invalid or expired token" });
        }
    };
};
exports.requireAdmin = requireAdmin;
//# sourceMappingURL=adminService.js.map