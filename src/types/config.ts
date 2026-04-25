
import { SignOptions } from "jsonwebtoken";
import { Redis } from "ioredis";
import { GoogleOAuthConfig } from "../oauth/types";
import { OAuthConfig } from "../oauth/types";
import type { OAuthIdentityAdapter } from "../oauth/adapters/redisAdapter";



export interface Authenik8Config {
  jwtSecret: string;
  jwtExpiry?: SignOptions["expiresIn"];
  refreshSecret: string;
  oauth?:OAuthConfig

  redis?: Redis; 
  identityAdapter?: OAuthIdentityAdapter;
  trustProxyHeaders?: boolean;
}
