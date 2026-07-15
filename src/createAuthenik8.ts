import { randomUUID } from "crypto";
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

const DEFAULT_ACCESS_TOKEN_EXPIRY = "15m";
const DEFAULT_REFRESH_TOKEN_EXPIRY = "7d";

export const createAuthenik8 = async (
  config: Authenik8Config
): Promise<Authenik8Instance> => {
  const redisClient = config.redis ?? (await initializeRedisClient());
  const tokenStore = new RedisTokenStore(redisClient);
  const accessTokenExpiry = config.jwtExpiry ?? DEFAULT_ACCESS_TOKEN_EXPIRY;

  const jwtService = new JWTService({
    jwtSecret: config.jwtSecret,
    jwk: config.jwt,
    expiry: accessTokenExpiry,
    redisClient,
    allowCookieAuth: config.allowCookieAuth ?? false,
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
      })
    : undefined;

  const issueTokens = async (payload: TokenPayload): Promise<TokenPair> => {
    const sessionId = payload.sessionId ?? randomUUID();
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
    config.identityAdapter ?? createRedisIdentityAdapter(redisClient),
    tokenService
  );

  const oauth = config.oauth
    ? createOAuth({
        ...config.oauth,
        redisClient,
        identityEngine,
      })
    : undefined;

  const security = new SecurityModule({
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
    requireAuth: jwtService.authenticateJWT,
    guestToken: jwtService.guestToken.bind(jwtService),
    getJwks: jwtService.getJwks.bind(jwtService),
    listSessions: jwtService.listSessions.bind(jwtService),
    revokeSession,
    revokeAllSessions,
    agent,

    refreshToken: refreshService.refresh.bind(refreshService),
    generateRefreshToken: refreshService.generateRefreshToken.bind(refreshService),

    rateLimit: security.rateLimiterMiddleware(),
    ipWhitelist: security.whiteListMiddleware(),
    helmet: security.helmetMiddleware(),
    addIP: security.addIP.bind(security),
    removeIP: security.removeIP.bind(security),
    listIPs: security.listIPs.bind(security),

    requireAdmin: requireAdmin({
      requireAuth: jwtService.authenticateJWT,
      store: redisClient,
      listSessions: jwtService.listSessions.bind(jwtService),
      revokeSession,
      revokeAllSessions,
    }),
    incognito: createIncognito({
      guestToken: jwtService.guestToken.bind(jwtService),
      verifyAccessToken: jwtService.verifyToken.bind(jwtService),
      verifyGuestToken: jwtService.verifyGuestToken.bind(jwtService),
    }),
    oauth,
    issueTokens,
  };
};
