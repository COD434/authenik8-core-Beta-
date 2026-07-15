import type { Redis } from "ioredis";
import type { Authenik8JwkConfig } from "../auth/jwk";
import type { OAuthConfig } from "../oauth/types";
import type { OAuthIdentityAdapter } from "../oauth/types";
import type { AgentIdentityConfig } from "../agent/types";



export interface Authenik8Config {
  /** @deprecated Configure `jwt` with ES256 JWKs for public-key verification. */
  jwtSecret?: string;
  jwt?: Authenik8JwkConfig;
  jwtExpiry?: string | number;
  refreshSecret: string;
  oauth?:OAuthConfig

  redis?: Redis; 
  identityAdapter?: OAuthIdentityAdapter;
  /** Enables fail-closed agent/service identity issuance and middleware. */
  agent?: AgentIdentityConfig;
  trustProxyHeaders?: boolean;
  allowCookieAuth?: boolean;
}
