import { randomUUID } from "crypto";
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

  const refreshService = new RefreshService({
    tokenStore,
    redisClient,
    accessTokenSecret: config.jwtSecret,
    refreshTokenSecret: config.refreshSecret,
    accessTokenExpiry,
    rotateRefreshTokens: true,
    refreshTokenExpiry: config.jwtExpiry ?? DEFAULT_REFRESH_TOKEN_EXPIRY,
  });

  const jwtService = new JWTService({
    jwtSecret: config.jwtSecret,
    expiry: accessTokenExpiry,
    redisClient,
    allowCookieAuth: config.allowCookieAuth ?? false,
  });

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
    guestToken: jwtService.guestToken.bind(jwtService),

    refreshToken: refreshService.refresh.bind(refreshService),
    generateRefreshToken: refreshService.generateRefreshToken.bind(refreshService),

    rateLimit: security.rateLimiterMiddleware(),
    ipWhitelist: security.whiteListMiddleware(),
    helmet: security.helmetMiddleware(),
    addIP: security.addIP.bind(security),
    removeIP: security.removeIP.bind(security),
    listIPs: security.listIPs.bind(security),

    requireAdmin: requireAdmin({
      jwtSecret: config.jwtSecret,
      store: redisClient,
      allowCookieAuth: config.allowCookieAuth ?? false,
    }),
    incognito: createIncognito({
      jwtSecret: config.jwtSecret,
      guestToken: jwtService.guestToken.bind(jwtService),
    }),
    oauth,
    issueTokens,
  };
};
