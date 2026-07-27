import type { RequestHandler } from "express";
import type { AuditEmitter } from "../audit/types";
import type { AuthorizationConfig, TenantResolver } from "./types";
export interface AuthorizationServiceOptions {
    authenticate: RequestHandler;
    config?: AuthorizationConfig;
    audit?: AuditEmitter;
}
export declare class AuthorizationService {
    private readonly authenticate;
    private readonly resolveTenant;
    private readonly audit;
    constructor(options: AuthorizationServiceOptions);
    requireRole(...roles: string[]): RequestHandler;
    requirePermission(...permissions: string[]): RequestHandler;
    requireScope(...scopes: string[]): RequestHandler;
    requireTenant(resolveTenant?: TenantResolver | undefined): RequestHandler<import("express-serve-static-core").ParamsDictionary, any, any, import("qs").ParsedQs, Record<string, any>>;
    private authorize;
    private runAuthentication;
    private deny;
}
//# sourceMappingURL=authorizationService.d.ts.map