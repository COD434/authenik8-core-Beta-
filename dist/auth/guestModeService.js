"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.createIncognito = void 0;
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const createIncognito = (options) => {
    return (req, res, next) => {
        const authHeader = req.headers.authorization;
        const token = authHeader?.startsWith("Bearer ")
            ? authHeader.split(" ")[1]
            : undefined;
        if (!token) {
            const guestToken = options.guestToken();
            const user = jsonwebtoken_1.default.verify(guestToken, options.jwtSecret);
            req.user = user;
            res.setHeader("X-Guest-Token", guestToken);
            return next();
        }
        try {
            const user = jsonwebtoken_1.default.verify(token, options.jwtSecret);
            req.user = {
                ...user,
                type: user.type ?? "authenticated",
            };
            return next();
        }
        catch {
            return res.status(401).json({ error: "Invalid or expired token" });
        }
    };
};
exports.createIncognito = createIncognito;
//# sourceMappingURL=guestModeService.js.map