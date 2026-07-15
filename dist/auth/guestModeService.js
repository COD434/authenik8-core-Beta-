"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.createIncognito = void 0;
const jwtAuth_1 = require("./jwtAuth");
const createIncognito = (options) => {
    const legacyVerifier = options.jwtSecret
        ? new jwtAuth_1.JWTService({ jwtSecret: options.jwtSecret })
        : undefined;
    const verifyAccessToken = options.verifyAccessToken ?? legacyVerifier?.verifyToken.bind(legacyVerifier);
    const verifyGuestToken = options.verifyGuestToken ?? legacyVerifier?.verifyGuestToken.bind(legacyVerifier);
    if (!verifyAccessToken || !verifyGuestToken) {
        throw new Error("Incognito mode requires token verification functions");
    }
    return async (req, res, next) => {
        const authHeader = req.headers.authorization;
        const token = authHeader?.startsWith("Bearer ")
            ? authHeader.slice("Bearer ".length).trim()
            : undefined;
        if (!token) {
            const guestToken = await options.guestToken();
            const user = await verifyGuestToken(guestToken);
            if (!user) {
                return res.status(500).json({ error: "Unable to issue guest token" });
            }
            req.user = user;
            res.setHeader("X-Guest-Token", guestToken);
            return next();
        }
        const user = await verifyAccessToken(token);
        if (!user) {
            return res.status(401).json({ error: "Invalid or expired token" });
        }
        req.user = {
            ...user,
            type: user.type ?? "authenticated",
        };
        return next();
    };
};
exports.createIncognito = createIncognito;
//# sourceMappingURL=guestModeService.js.map