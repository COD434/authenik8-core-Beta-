"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.createAuthenik8 = void 0;
const crypto_1 = require("crypto");
const refreshService_1 = require("./auth/refreshService");
const guestModeService_1 = require("./auth/guestModeService");
const jwtAuth_1 = require("./auth/jwtAuth");
const adminService_1 = require("./middleware/adminService");
const identityEngine_1 = require("./oauth/brain/identityEngine");
const core_1 = require("./oauth/core");
const redisAdapter_1 = require("./oauth/adapters/redisAdapter");
const redisService_1 = require("./redis/redisService");
const ipService_1 = require("./security/ipService");
const RedisTokenStore_1 = require("./storage/RedisTokenStore");
const DEFAULT_ACCESS_TOKEN_EXPIRY = "15m";
const DEFAULT_REFRESH_TOKEN_EXPIRY = "7d";
const createAuthenik8 = async (config) => {
    const redisClient = config.redis ?? (await (0, redisService_1.initializeRedisClient)());
    const tokenStore = new RedisTokenStore_1.RedisTokenStore(redisClient);
    const accessTokenExpiry = config.jwtExpiry ?? DEFAULT_ACCESS_TOKEN_EXPIRY;
    const refreshService = new refreshService_1.RefreshService({
        tokenStore,
        redisClient,
        accessTokenSecret: config.jwtSecret,
        refreshTokenSecret: config.refreshSecret,
        accessTokenExpiry,
        rotateRefreshTokens: true,
        refreshTokenExpiry: config.jwtExpiry ?? DEFAULT_REFRESH_TOKEN_EXPIRY,
    });
    const jwtService = new jwtAuth_1.JWTService({
        jwtSecret: config.jwtSecret,
        expiry: accessTokenExpiry,
        redisClient,
        allowCookieAuth: config.allowCookieAuth ?? false,
    });
    const issueTokens = async (payload) => {
        const sessionId = payload.sessionId ?? (0, crypto_1.randomUUID)();
        const tokenPayload = { ...payload, sessionId };
        const accessToken = await jwtService.signToken(tokenPayload);
        const refreshToken = await refreshService.generateRefreshToken({
            userId: tokenPayload.userId,
            email: tokenPayload.email,
            sessionId,
        });
        return { accessToken, refreshToken };
    };
    const tokenService = {
        signAccessToken: jwtService.signToken.bind(jwtService),
        generateRefreshToken: refreshService.generateRefreshToken.bind(refreshService),
    };
    const identityEngine = (0, identityEngine_1.createIdentityEngine)(config.identityAdapter ?? (0, redisAdapter_1.createRedisIdentityAdapter)(redisClient), tokenService);
    const oauth = config.oauth
        ? (0, core_1.createOAuth)({
            ...config.oauth,
            redisClient,
            identityEngine,
        })
        : undefined;
    const security = new ipService_1.SecurityModule({
        redisClient,
        rateLimiterEnabled: true,
        helmetEnabled: true,
        whiteListEnabled: true,
        trustProxyHeaders: config.trustProxyHeaders ?? false,
    });
    return {
        redisclient: redisClient,
        signToken: jwtService.signToken.bind(jwtService),
        verifyToken: jwtService.verifyToken.bind(jwtService),
        guestToken: jwtService.guestToken.bind(jwtService),
        refreshToken: refreshService.refresh.bind(refreshService),
        generateRefreshToken: refreshService.generateRefreshToken.bind(refreshService),
        rateLimit: security.rateLimiterMiddleware(),
        ipWhitelist: security.whiteListMiddleware(),
        helmet: security.helmetMiddleware(),
        addIP: security.addIP.bind(security),
        removeIP: security.removeIP.bind(security),
        listIPs: security.listIPs.bind(security),
        requireAdmin: (0, adminService_1.requireAdmin)({
            jwtSecret: config.jwtSecret,
            store: redisClient,
            allowCookieAuth: config.allowCookieAuth ?? false,
        }),
        incognito: (0, guestModeService_1.createIncognito)({
            jwtSecret: config.jwtSecret,
            guestToken: jwtService.guestToken.bind(jwtService),
        }),
        oauth,
        issueTokens,
    };
};
exports.createAuthenik8 = createAuthenik8;
//# sourceMappingURL=createAuthenik8.js.map