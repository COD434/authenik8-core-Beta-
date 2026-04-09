
import { SignOptions } from "jsonwebtoken";
import { Redis } from "ioredis";
import { GoogleOAuthConfig } from "../oauth/types";
import { OAuthConfig } from "../oauth/types";



export interface Authenik8Config {
  jwtSecret: string;
  jwtExpiry?: SignOptions["expiresIn"];
  refreshSecret: string;
  oauth?:OAuthConfig

  redis?: Redis; 
}

