"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.createAuthenik8 = void 0;
const ipService_1 = require("./security/ipService");
const refreshService_1 = require("./auth/refreshService");
const guestModeService_1 = require("./auth/guestModeService");
const adminService_1 = require("./middleware/adminService");
const jwtAuth_1 = require("./auth/jwtAuth");
const redisService_1 = require("./redis/redisService");
const RedisTokenStore_1 = require("./storage/RedisTokenStore");
const core_1 = require("./oauth/core");
const identityEngine_1 = require("./oauth/brain/identityEngine");
const redisAdapter_1 = require("./oauth/adapters/redisAdapter");
const createAuthenik8 = async (config) => {
    const redisClient = config.redis ?? await (0, redisService_1.initializeRedisClient)();
    const tokenStore = new RedisTokenStore_1.RedisTokenStore(redisClient);
    const refreshService = new refreshService_1.RefreshService({
        tokenStore,
        redisClient,
        accessTokenSecret: config.jwtSecret,
        refreshTokenSecret: config.refreshSecret,
        accessTokenExpiry: config.jwtExpiry ?? "15m",
        rotateRefreshTokens: true,
        refreshTokenExpiry: config.jwtExpiry ?? "7d",
    });
    const jwtService = new jwtAuth_1.JWTService({
        jwtSecret: config.jwtSecret,
        expiry: config.jwtExpiry ?? "15m",
        redisClient: redisClient
    });
    const issueTokens = async (payload) => {
        const accessToken = jwtService.signToken(payload);
        const refreshToken = await refreshService.generateRefreshToken({
            userId: payload.userId,
            email: payload.email,
        });
        return {
            accessToken,
            refreshToken,
        };
    };
    const tokenService = {
        signAccessToken: jwtService.signToken.bind(jwtService),
        generateRefreshToken: refreshService.generateRefreshToken.bind(refreshService),
    };
    // =========================
    // 5. Identity Engine (NO circular deps)
    // =========================
    const identityEngine = (0, identityEngine_1.createIdentityEngine)(config.identityAdapter ?? (0, redisAdapter_1.createRedisIdentityAdapter)(redisClient), tokenService);
    // =========================
    // 6. OAuth (depends on identity engine)
    // =========================
    const oauth = config.oauth
        ? (0, core_1.createOAuth)({
            ...config.oauth,
            redisClient,
            identityEngine,
        })
        : undefined;
    // ===============
    const issueTokensFromProfile = async (profile) => {
        if (!isVerifiedOAuthEmail(profile.email_verified)) {
            throw new Error("OAuth profile email must be verified before issuing tokens");
        }
        const result = await identityEngine.resolveOAuth({
            profile,
            mode: "login",
            userId: null,
        });
        if (result.type === "EXISTING_PROVIDER_LOGIN" ||
            result.type === "NEW_USER_CREATION") {
            return {
                accessToken: result.accessToken,
                refreshToken: result.refreshToken,
            };
        }
        if (result.type === "LINK_REQUIRED") {
            throw new Error(result.message);
        }
        throw new Error("OAuth token issuance failed");
    };
    const security = new ipService_1.SecurityModule({
        redisClient: redisClient,
        rateLimiterEnabled: true,
        helmetEnabled: true,
        whiteListEnabled: true,
        trustProxyHeaders: config.trustProxyHeaders ?? false,
    });
    return {
        //auth
        redis: redisClient,
        signToken: jwtService.signToken.bind(jwtService),
        verifyToken: jwtService.verifyToken.bind(jwtService),
        guestToken: jwtService.guestToken.bind(jwtService),
        //refresh
        refreshToken: refreshService.refresh.bind(refreshService),
        generateRefreshToken: refreshService.generateRefreshToken.bind(refreshService),
        //security
        rateLimit: security.rateLimiterMiddleware(),
        ipWhitelist: security.whiteListMiddleware(),
        helmet: security.helmetMiddleware(),
        //Whitelist management
        addIP: security.addIP.bind(security),
        removeIP: security.removeIP.bind(security),
        listIPs: security.listIPs.bind(security),
        //middleware
        requireAdmin: (0, adminService_1.requireAdmin)({ jwtSecret: config.jwtSecret,
            redis: redisClient
        }),
        incognito: (0, guestModeService_1.createIncognito)({
            jwtSecret: config.jwtSecret,
            guestToken: jwtService.guestToken.bind(jwtService),
        }),
        oauth,
        issueTokens,
        issueTokensFromProfile
    };
};
exports.createAuthenik8 = createAuthenik8;
const isVerifiedOAuthEmail = (value) => value === true || value === "true";
//# sourceMappingURL=createAuthenik8.js.map