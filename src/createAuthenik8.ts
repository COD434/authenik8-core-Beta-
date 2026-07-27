import { randomUUID, timingSafeEqual } from "crypto";
import { AgentIdentityService } from "./agent/agentIdentity";
import { RefreshService } from "./auth/refreshService";
import { createIncognito } from "./auth/guestModeService";
import { JWTService } from "./auth/jwtAuth";
import { requireAdmin } from "./middleware/adminService";
import { createIdentityEngine } from "./oauth/brain/identityEngine";
import { createOAuth } from "./oauth/core";
import { createRedisIdentityAdapter } from "./oauth/adapters/redisAdapter";
import { initializeRedisClient } from "./redis/redisService";
import { SecurityModule } from "./security/ipService";
import { RedisTokenStore } from "./storage/RedisTokenStore";
import { Authenik8Config } from "./types/config";
import { Authenik8Instance } from "./types/public";
import { TokenPayload, TokenPair } from "./types/tokens";
import { AuditDispatcher } from "./audit/auditDispatcher";
import { AuthorizationService } from "./authorization/authorizationService";
import { SessionRiskService } from "./risk/sessionRiskService";
import { RedisSessionRiskStore } from "./risk/redisSessionRiskStore";
import type { SessionObservation } from "./risk/types";
import { createSessionObservationResolver } from "./security/requestContext";
import {
  DEFAULT_TOKEN_AUDIENCE,
  DEFAULT_TOKEN_ISSUER,
} from "./auth/jwk";
import { resolveRedisKeyPrefix } from "./redis/keyNamespace";
import { resolveIdentityPolicy } from "./oauth/brain/identityPolicy";

const DEFAULT_ACCESS_TOKEN_EXPIRY = "15m";
const DEFAULT_REFRESH_TOKEN_EXPIRY = "7d";

export const createAuthenik8 = async (
  config: Authenik8Config
): Promise<Authenik8Instance> => {
  const secretBytes = (secret: unknown, label: string): Buffer => {
    if (
      typeof secret !== "string" ||
      Buffer.byteLength(secret, "utf8") < 32 ||
      Buffer.byteLength(secret, "utf8") > 4096
    ) {
      throw new Error(`${label} must contain between 32 and 4096 bytes`);
    }
    return Buffer.from(secret, "utf8");
  };
  const refreshSecretBytes = secretBytes(
    config.refreshSecret,
    "refreshSecret",
  );
  let jwtSecretBytes: Buffer | undefined;
  if (!config.jwt) {
    jwtSecretBytes = secretBytes(config.jwtSecret, "jwtSecret");
  } else if (config.jwtSecret !== undefined) {
    jwtSecretBytes = secretBytes(config.jwtSecret, "jwtSecret");
  }
  if (
    jwtSecretBytes &&
    jwtSecretBytes.length === refreshSecretBytes.length &&
    timingSafeEqual(jwtSecretBytes, refreshSecretBytes)
  ) {
    throw new Error(
      "jwtSecret and refreshSecret must be independent cryptographic secrets",
    );
  }
  if (
    config.trustProxyHeaders === true &&
    (!config.trustedProxyCidrs || config.trustedProxyCidrs.length === 0)
  ) {
    throw new Error(
      "trustProxyHeaders requires at least one trustedProxyCidrs network",
    );
  }
  const resolveSessionObservation = createSessionObservationResolver(
    config.trustedProxyCidrs ?? [],
  );
  const redisKeyPrefix = resolveRedisKeyPrefix(
    config.redisKeyPrefix,
    config.jwt?.issuer ?? DEFAULT_TOKEN_ISSUER,
    config.jwt?.audience ?? DEFAULT_TOKEN_AUDIENCE,
  );
  const redisClient = config.redis ?? (await initializeRedisClient());
  const tokenStore = new RedisTokenStore(
    redisClient,
    false,
    `${redisKeyPrefix}:legacy`,
  );
  const accessTokenExpiry = config.jwtExpiry ?? DEFAULT_ACCESS_TOKEN_EXPIRY;
  const audit = new AuditDispatcher(config.audit);
  const risk = new SessionRiskService(
    new RedisSessionRiskStore(redisClient),
    config.risk,
    audit,
    `${redisKeyPrefix}:risk`,
  );

  const jwtService = new JWTService({
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

  const refreshService = new RefreshService({
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
    ? new AgentIdentityService({
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

  const issueTokens = async (
    payload: TokenPayload,
    observation?: SessionObservation,
  ): Promise<TokenPair> => {
    const sessionId = payload.sessionId ?? randomUUID();
    const tokenPayload = { ...payload, sessionId };
    const accessToken = observation
      ? await jwtService.signToken(tokenPayload, observation)
      : await jwtService.signToken(tokenPayload);
    let refreshToken: string;
    try {
      refreshToken = await refreshService.generateRefreshToken({
        userId: tokenPayload.userId,
        email: tokenPayload.email,
        sessionId,
      });
    } catch (error) {
      await jwtService.revokeSession(tokenPayload.userId, sessionId);
      throw error;
    }

    return { accessToken, refreshToken };
  };

  const tokenService = { issueTokens };

  const revokeSession = async (userId: string, sessionId: string) => {
    await refreshService.revokeSession(userId, sessionId);
  };

  const revokeAllSessions = async (userId: string) => {
    const sessions = await jwtService.listSessions(userId);
    await refreshService.revokeAllSessions(
      userId,
      sessions.map((session) => session.sessionId),
    );
  };

  const identityEngine = createIdentityEngine(
    config.identityAdapter ??
      createRedisIdentityAdapter(redisClient, `${redisKeyPrefix}:oauth:v1`),
    tokenService,
    audit,
    resolveIdentityPolicy(config.oauthIdentityPolicy),
  );

  const oauth = config.oauth
    ? createOAuth({
        ...config.oauth,
        redisClient,
        identityEngine,
        audit,
        keyPrefix: `${redisKeyPrefix}:oauth`,
      })
    : undefined;

  const security = new SecurityModule({
    ...config.security,
    redisClient,
    trustProxyHeaders: config.trustProxyHeaders ?? false,
    trustedProxyCidrs: config.trustedProxyCidrs,
    audit,
    keyPrefix: `${redisKeyPrefix}:security`,
  });
  const authorization = new AuthorizationService({
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

    requireAdmin: requireAdmin({
      requireAuth: authorization.requireRole("admin"),
      store: redisClient,
      listSessions: jwtService.listSessions.bind(jwtService),
      revokeSession,
      revokeAllSessions,
    }),
    requireRole: (...roles) => authorization.requireRole(...roles),
    requirePermission: (...permissions) =>
      authorization.requirePermission(...permissions),
    requireScope: (...scopes) => authorization.requireScope(...scopes),
    requireTenant: (resolveTenant) =>
      authorization.requireTenant(resolveTenant),
    incognito: createIncognito({
      guestToken: jwtService.guestToken.bind(jwtService),
      verifyAccessToken: jwtService.verifyActiveToken.bind(jwtService),
      verifyGuestToken: jwtService.verifyGuestToken.bind(jwtService),
    }),
    oauth,
    issueTokens,
  };
};
