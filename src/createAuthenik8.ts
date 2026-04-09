import {SecurityModule} from "./security/ipService";
import  {RefreshService } from "./auth/refreshService"
import {Authenik8Config} from "./types/config";
import  {Incognito} from "./auth/guestModeService"
import {requireAdmin} from "./middleware/adminService";
import {JWTService} from "./auth/jwtAuth"
import { initializeRedisClient } from "./redis/redisService"
import {Authenik8Instance} from "./types/public"
import {RedisTokenStore} from "./storage/RedisTokenStore"
import { createOAuth } from "./oauth/core";
import { TokenPayload, TokenPair } from "./types/tokens";
import { OAuthProfile } from "./oauth/types";
import { createIdentityEngine } from "./oauth/brain/identityEngine";
import { memoryAdapter } from "./oauth/adapters/memoryAdapter";


export const createAuthenik8 = async (config:Authenik8Config): Promise<Authenik8Instance> =>{
	


const redisClient = config.redis ?? await initializeRedisClient()


const tokenStore = new RedisTokenStore(redisClient);



const refreshService = new RefreshService({
    tokenStore,
    redisClient,
    accessTokenSecret: config.jwtSecret,
    refreshTokenSecret: config.refreshSecret,
    accessTokenExpiry: config.jwtExpiry ?? "15m",
    rotateRefreshTokens: true,
    refreshTokenExpiry: config.jwtExpiry ?? "7d",
  });


	const jwtService =new JWTService({
	jwtSecret:config.jwtSecret,
	expiry:config.jwtExpiry ?? "15m",
	redisClient:redisClient
	});



	const issueTokens = async (payload: TokenPayload): Promise<TokenPair> => {
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
  const identityEngine = createIdentityEngine(
    memoryAdapter,
    tokenService
  );

  // =========================
  // 6. OAuth (depends on identity engine)
  // =========================
  const oauth = config.oauth
    ? createOAuth({
        ...config.oauth,
        redisClient,
        identityEngine,
      })
    : undefined;

  // ===============
const issueTokensFromProfile = async (
  profile: OAuthProfile
): Promise<TokenPair> => {
  return issueTokens({
    userId: profile.providerId,
    email: profile.email,
    role: "user",
  });
};

	const security = new SecurityModule({
	redisClient:redisClient,
	rateLimiterEnabled: true,
	helmetEnabled:true,
	whiteListEnabled:true
	});
return{
	//auth
	redis:redisClient,
	signToken:jwtService.signToken.bind(jwtService),
	verifyToken:jwtService.verifyToken.bind(jwtService),
	guestToken:jwtService.guestToken.bind(jwtService),
	
	//refresh
	refreshToken:
		refreshService.refresh.bind(refreshService),
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
requireAdmin :requireAdmin({ jwtSecret:
	config.jwtSecret,
			   redis:redisClient
}),
incognito:Incognito,
oauth,
issueTokens,
issueTokensFromProfile
}
}
