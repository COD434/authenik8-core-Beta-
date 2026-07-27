import type { Redis } from "ioredis";
import type { HelmetOptions } from "helmet";
import type { AgentIdentityConfig } from "../agent/types";
import type { AuditConfig } from "../audit/types";
import type { Authenik8JwkConfig } from "../auth/jwk";
import type { AuthorizationConfig } from "../authorization/types";
import type { IdentityPolicyConfig } from "../oauth/brain/identityPolicy";
import type { OAuthConfig, OAuthIdentityAdapter } from "../oauth/types";
import type { SessionRiskConfig } from "../risk/types";

export interface Authenik8SecurityConfig {
  rateLimitPoints?: number;
  rateLimitDuration?: number;
  rateLimitBlock?: number;
  rateLimiterEnabled?: boolean;
  whiteListEnabled?: boolean;
  helmetEnabled?: boolean;
  /** Replaces the SDK's enforcing Helmet defaults when supplied. */
  helmetOptions?: HelmetOptions;
}

export interface Authenik8Config {
  /** @deprecated Configure `jwt` with ES256 JWKs for public-key verification. */
  jwtSecret?: string;
  jwt?: Authenik8JwkConfig;
  jwtExpiry?: string | number;
  refreshSecret: string;
  oauth?: OAuthConfig;
  redis?: Redis;
  /**
   * Isolates all SDK-owned Redis keys. When omitted, a stable prefix is derived
   * from the configured JWT issuer and audience.
   */
  redisKeyPrefix?: string;
  identityAdapter?: OAuthIdentityAdapter;
  /** OAuth email-link policy. Both automatic modes are disabled by default. */
  oauthIdentityPolicy?: IdentityPolicyConfig;
  /** Enables fail-closed agent/service identity issuance and middleware. */
  agent?: AgentIdentityConfig;
  /** Structured security events are delivered to application-owned sinks. */
  audit?: AuditConfig;
  /** Human role, permission, scope, and tenant authorization policy. */
  authorization?: AuthorizationConfig;
  /** Stateful anomaly detection and automatic session quarantine policy. */
  risk?: SessionRiskConfig;
  /** HTTP rate-limit, IP allowlist, and Helmet policy. */
  security?: Authenik8SecurityConfig;
  /**
   * @deprecated Use `trustedProxyCidrs`. A blanket proxy trust boolean is not
   * sufficient to authenticate the sender of forwarding headers.
   */
  trustProxyHeaders?: boolean;
  /**
   * Networks containing reverse proxies that are authorized to set
   * `X-Forwarded-For`. The socket peer and every trusted hop are verified.
   */
  trustedProxyCidrs?: readonly string[];
  allowCookieAuth?: boolean;
}
