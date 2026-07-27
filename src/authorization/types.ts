import type { Request } from "express";

export type TenantResolver = (
  request: Request,
) => string | undefined | Promise<string | undefined>;

export interface AuthorizationConfig {
  /**
   * When configured, every role, permission, and scope check also requires the
   * authenticated principal to belong to the resolved tenant.
   */
  resolveTenant?: TenantResolver;
}
