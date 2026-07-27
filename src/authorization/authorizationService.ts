import type {
  NextFunction,
  Request,
  RequestHandler,
  Response,
} from "express";
import type { AuditEmitter } from "../audit/types";
import type { JwtPayload } from "../auth/jwtAuth";
import type { AuthorizationConfig, TenantResolver } from "./types";
import { isAuthenik8Authenticated } from "../auth/requestIdentity";
import { containsControlCharacter } from "../utility/safeString";

const MAX_REQUIREMENTS = 64;
const AUTHORIZATION_DENIED = {
  error: {
    code: "AUTHORIZATION_DENIED",
    message: "The authenticated principal does not have the required authority",
  },
};

type ClaimName = "permissions" | "scopes";
type AuthenticatedRequest = Request & { user?: JwtPayload };

export interface AuthorizationServiceOptions {
  authenticate: RequestHandler;
  config?: AuthorizationConfig;
  audit?: AuditEmitter;
}

const normalizeRequirements = (
  values: readonly string[],
  label: string,
): string[] => {
  const normalized = [...new Set(values.map((value) => value.trim()))];
  if (
    !normalized.length ||
    normalized.length > MAX_REQUIREMENTS ||
    normalized.some(
      (value) =>
        !value ||
        value.length > 128 ||
        containsControlCharacter(value),
    )
  ) {
    throw new Error(
      `${label} requires between 1 and ${MAX_REQUIREMENTS} non-empty values of at most 128 characters`,
    );
  }
  return normalized;
};

const boundedRequestString = (
  value: unknown,
  maximumLength: number,
): string | undefined =>
  typeof value === "string" &&
  value.length > 0 &&
  value.length <= maximumLength &&
  !containsControlCharacter(value)
    ? value
    : undefined;

const stringArray = (value: unknown): string[] =>
  Array.isArray(value)
    ? value.filter((item): item is string => typeof item === "string")
    : [];

const grantedRoles = (user: JwtPayload): Set<string> =>
  new Set([
    ...(typeof user.role === "string" ? [user.role] : []),
    ...stringArray(user.roles),
  ]);

const grantedClaims = (
  user: JwtPayload,
  claim: ClaimName,
): Set<string> => {
  const values = stringArray(user[claim]);
  if (claim === "scopes" && typeof user.scope === "string") {
    values.push(...user.scope.split(/\s+/).filter(Boolean));
  }
  return new Set(values);
};

const tenantIds = (user: JwtPayload): Set<string> =>
  new Set([
    ...(typeof user.tenantId === "string" ? [user.tenantId] : []),
    ...stringArray(user.tenantIds),
  ]);

export class AuthorizationService {
  private readonly authenticate;
  private readonly resolveTenant;
  private readonly audit;

  constructor(options: AuthorizationServiceOptions) {
    this.authenticate = options.authenticate;
    this.resolveTenant = options.config?.resolveTenant;
    this.audit = options.audit;
  }

  requireRole(...roles: string[]): RequestHandler {
    const required = normalizeRequirements(roles, "requireRole");
    return this.authorize("role", required, (user) => {
      const granted = grantedRoles(user);
      return required.some((role) => granted.has(role));
    });
  }

  requirePermission(...permissions: string[]): RequestHandler {
    const required = normalizeRequirements(
      permissions,
      "requirePermission",
    );
    return this.authorize("permission", required, (user) => {
      const granted = grantedClaims(user, "permissions");
      return required.every((permission) => granted.has(permission));
    });
  }

  requireScope(...scopes: string[]): RequestHandler {
    const required = normalizeRequirements(scopes, "requireScope");
    return this.authorize("scope", required, (user) => {
      const granted = grantedClaims(user, "scopes");
      return required.every((scope) => granted.has(scope));
    });
  }

  requireTenant(resolveTenant: TenantResolver | undefined = this.resolveTenant) {
    if (!resolveTenant) {
      throw new Error(
        "requireTenant needs authorization.resolveTenant or an explicit resolver",
      );
    }
    return this.authorize("tenant", [], () => true, resolveTenant);
  }

  private authorize(
    kind: "role" | "permission" | "scope" | "tenant",
    required: readonly string[],
    claimsAllow: (user: JwtPayload) => boolean,
    tenantResolver = this.resolveTenant,
  ): RequestHandler {
    return async (req: Request, res: Response, next: NextFunction) => {
      const authenticated = await this.runAuthentication(req, res);
      if (!authenticated) return;

      const user = (req as AuthenticatedRequest).user;
      if (!user) {
        await this.deny(req, res, kind, required, undefined);
        return;
      }

      const requestedTenant = tenantResolver
        ? boundedRequestString(await tenantResolver(req), 256)
        : undefined;
      const tenantAllowed =
        !tenantResolver ||
        (!!requestedTenant && tenantIds(user).has(requestedTenant));

      if (!claimsAllow(user) || !tenantAllowed) {
        await this.deny(req, res, kind, required, requestedTenant, user);
        return;
      }

      return next();
    };
  }

  private async runAuthentication(
    req: Request,
    res: Response,
  ): Promise<boolean> {
    if (isAuthenik8Authenticated(req)) return true;

    let authenticated = false;
    await Promise.resolve(
      this.authenticate(req, res, () => {
        authenticated = true;
      }),
    );
    return authenticated;
  }

  private async deny(
    req: Request,
    res: Response,
    kind: string,
    required: readonly string[],
    tenantId?: string,
    user?: JwtPayload,
  ): Promise<void> {
    await this.audit?.emit({
      type: "authorization.denied",
      severity: "warning",
      outcome: "denied",
      actor: {
        type: "user",
        ...(typeof user?.userId === "string" ? { id: user.userId } : {}),
      },
      ...(typeof user?.sessionId === "string"
        ? { sessionId: user.sessionId }
        : {}),
      ...(tenantId ? { tenantId } : {}),
      correlationId:
        boundedRequestString(req.headers["x-request-id"], 128),
      metadata: { kind, required: [...required] },
    });
    res.status(403).json(AUTHORIZATION_DENIED);
  }
}
