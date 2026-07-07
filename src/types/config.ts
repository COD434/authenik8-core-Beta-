import type { SignOptions } from "jsonwebtoken";
import type { Redis } from "ioredis";
import type { OAuthConfig } from "../oauth/types";
import type { OAuthIdentityAdapter } from "../oauth/identity/types";



export interface Authenik8Config {
  jwtSecret: string;
  jwtExpiry?: SignOptions["expiresIn"];
  refreshSecret: string;
  oauth?:OAuthConfig

  redis?: Redis; 
  identityAdapter?: OAuthIdentityAdapter;
  trustProxyHeaders?: boolean;
  allowCookieAuth?: boolean;
}
