"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.createAuthenik8 = void 0;
const crypto_1 = require("crypto");
const agentIdentity_1 = require("./agent/agentIdentity");
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
const auditDispatcher_1 = require("./audit/auditDispatcher");
const authorizationService_1 = require("./authorization/authorizationService");
const sessionRiskService_1 = require("./risk/sessionRiskService");
const redisSessionRiskStore_1 = require("./risk/redisSessionRiskStore");
const requestContext_1 = require("./security/requestContext");
const jwk_1 = require("./auth/jwk");
const keyNamespace_1 = require("./redis/keyNamespace");
const identityPolicy_1 = require("./oauth/brain/identityPolicy");
const DEFAULT_ACCESS_TOKEN_EXPIRY = "15m";
const DEFAULT_REFRESH_TOKEN_EXPIRY = "7d";
const createAuthenik8 = async (config) => {
    const secretBytes = (secret, label) => {
        if (typeof secret !== "string" ||
            Buffer.byteLength(secret, "utf8") < 32 ||
            Buffer.byteLength(secret, "utf8") > 4096) {
            throw new Error(`${label} must contain between 32 and 4096 bytes`);
        }
        return Buffer.from(secret, "utf8");
    };
    const refreshSecretBytes = secretBytes(config.refreshSecret, "refreshSecret");
    let jwtSecretBytes;
    if (!config.jwt) {
        jwtSecretBytes = secretBytes(config.jwtSecret, "jwtSecret");
    }
    else if (config.jwtSecret !== undefined) {
        jwtSecretBytes = secretBytes(config.jwtSecret, "jwtSecret");
    }
    if (jwtSecretBytes &&
        jwtSecretBytes.length === refreshSecretBytes.length &&
        (0, crypto_1.timingSafeEqual)(jwtSecretBytes, refreshSecretBytes)) {
        throw new Error("jwtSecret and refreshSecret must be independent cryptographic secrets");
    }
    if (config.trustProxyHeaders === true &&
        (!config.trustedProxyCidrs || config.trustedProxyCidrs.length === 0)) {
        throw new Error("trustProxyHeaders requires at least one trustedProxyCidrs network");
    }
    const resolveSessionObservation = (0, requestContext_1.createSessionObservationResolver)(config.trustedProxyCidrs ?? []);
    const redisKeyPrefix = (0, keyNamespace_1.resolveRedisKeyPrefix)(config.redisKeyPrefix, config.jwt?.issuer ?? jwk_1.DEFAULT_TOKEN_ISSUER, config.jwt?.audience ?? jwk_1.DEFAULT_TOKEN_AUDIENCE);
    const redisClient = config.redis ?? (await (0, redisService_1.initializeRedisClient)());
    const tokenStore = new RedisTokenStore_1.RedisTokenStore(redisClient, false, `${redisKeyPrefix}:legacy`);
    const accessTokenExpiry = config.jwtExpiry ?? DEFAULT_ACCESS_TOKEN_EXPIRY;
    const audit = new auditDispatcher_1.AuditDispatcher(config.audit);
    const risk = new sessionRiskService_1.SessionRiskService(new redisSessionRiskStore_1.RedisSessionRiskStore(redisClient), config.risk, audit, `${redisKeyPrefix}:risk`);
    const jwtService = new jwtAuth_1.JWTService({
        jwtSecret: config.jwtSecret,
        jwk: config.jwt,
        expiry: accessTokenExpiry,
        redisClient,
        allowCookieAuth: config.allowCookieAuth ?? false,
        audit,
        risk,
        resolveRequestContext: resolveSessionObservation,
        sessionKeyPrefix: `${redisKeyPrefix}:sessions`,
    });
    const refreshService = new refreshService_1.RefreshService({
        tokenStore,
        redisClient,
        refreshTokenSecret: config.refreshSecret,
        accessTokenSigner: (payload) => jwtService.signToken(payload),
        issuer: jwtService.issuer,
        audience: jwtService.audience,
        rotateRefreshTokens: true,
        refreshTokenExpiry: DEFAULT_REFRESH_TOKEN_EXPIRY,
        audit,
        risk,
        keyPrefix: redisKeyPrefix,
    });
    const agent = config.agent
        ? new agentIdentity_1.AgentIdentityService({
            config: config.agent,
            redisClient,
            jwk: config.jwt,
            legacySecret: config.jwtSecret,
            issuer: jwtService.issuer,
            audience: jwtService.audience,
            verifyHumanToken: jwtService.verifyActiveToken.bind(jwtService),
            hasHumanSession: jwtService.hasActiveSession.bind(jwtService),
            audit,
            risk,
            keyPrefix: redisKeyPrefix,
        })
        : undefined;
    const issueTokens = async (payload, observation) => {
        const sessionId = payload.sessionId ?? (0, crypto_1.randomUUID)();
        const tokenPayload = { ...payload, sessionId };
        const accessToken = observation
            ? await jwtService.signToken(tokenPayload, observation)
            : await jwtService.signToken(tokenPayload);
        let refreshToken;
        try {
            refreshToken = await refreshService.generateRefreshToken({
                userId: tokenPayload.userId,
                email: tokenPayload.email,
                sessionId,
            });
        }
        catch (error) {
            await jwtService.revokeSession(tokenPayload.userId, sessionId);
            throw error;
        }
        return { accessToken, refreshToken };
    };
    const tokenService = { issueTokens };
    const revokeSession = async (userId, sessionId) => {
        await refreshService.revokeSession(userId, sessionId);
    };
    const revokeAllSessions = async (userId) => {
        const sessions = await jwtService.listSessions(userId);
        await refreshService.revokeAllSessions(userId, sessions.map((session) => session.sessionId));
    };
    const identityEngine = (0, identityEngine_1.createIdentityEngine)(config.identityAdapter ??
        (0, redisAdapter_1.createRedisIdentityAdapter)(redisClient, `${redisKeyPrefix}:oauth:v1`), tokenService, audit, (0, identityPolicy_1.resolveIdentityPolicy)(config.oauthIdentityPolicy));
    const oauth = config.oauth
        ? (0, core_1.createOAuth)({
            ...config.oauth,
            redisClient,
            identityEngine,
            audit,
            keyPrefix: `${redisKeyPrefix}:oauth`,
        })
        : undefined;
    const security = new ipService_1.SecurityModule({
        ...config.security,
        redisClient,
        trustProxyHeaders: config.trustProxyHeaders ?? false,
        trustedProxyCidrs: config.trustedProxyCidrs,
        audit,
        keyPrefix: `${redisKeyPrefix}:security`,
    });
    const authorization = new authorizationService_1.AuthorizationService({
        authenticate: jwtService.authenticateJWT,
        config: config.authorization,
        audit,
    });
    return {
        redisclient: redisClient,
        signToken: jwtService.signToken.bind(jwtService),
        verifyToken: jwtService.verifyToken.bind(jwtService),
        verifyActiveToken: jwtService.verifyActiveToken.bind(jwtService),
        requireAuth: jwtService.authenticateJWT,
        guestToken: jwtService.guestToken.bind(jwtService),
        getJwks: jwtService.getJwks.bind(jwtService),
        listSessions: jwtService.listSessions.bind(jwtService),
        revokeSession,
        revokeAllSessions,
        agent,
        audit,
        risk,
        refreshToken: refreshService.refresh.bind(refreshService),
        generateRefreshToken: refreshService.generateRefreshToken.bind(refreshService),
        rateLimit: security.rateLimiterMiddleware(),
        ipWhitelist: security.whiteListMiddleware(),
        helmet: security.helmetMiddleware(),
        addIP: security.addIP.bind(security),
        removeIP: security.removeIP.bind(security),
        listIPs: security.listIPs.bind(security),
        requireAdmin: (0, adminService_1.requireAdmin)({
            requireAuth: authorization.requireRole("admin"),
            store: redisClient,
            listSessions: jwtService.listSessions.bind(jwtService),
            revokeSession,
            revokeAllSessions,
        }),
        requireRole: (...roles) => authorization.requireRole(...roles),
        requirePermission: (...permissions) => authorization.requirePermission(...permissions),
        requireScope: (...scopes) => authorization.requireScope(...scopes),
        requireTenant: (resolveTenant) => authorization.requireTenant(resolveTenant),
        incognito: (0, guestModeService_1.createIncognito)({
            guestToken: jwtService.guestToken.bind(jwtService),
            verifyAccessToken: jwtService.verifyActiveToken.bind(jwtService),
            verifyGuestToken: jwtService.verifyGuestToken.bind(jwtService),
        }),
        oauth,
        issueTokens,
    };
};
exports.createAuthenik8 = createAuthenik8;
//# sourceMappingURL=createAuthenik8.js.map