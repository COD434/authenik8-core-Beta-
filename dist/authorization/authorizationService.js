"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.AuthorizationService = void 0;
const requestIdentity_1 = require("../auth/requestIdentity");
const safeString_1 = require("../utility/safeString");
const MAX_REQUIREMENTS = 64;
const AUTHORIZATION_DENIED = {
    error: {
        code: "AUTHORIZATION_DENIED",
        message: "The authenticated principal does not have the required authority",
    },
};
const normalizeRequirements = (values, label) => {
    const normalized = [...new Set(values.map((value) => value.trim()))];
    if (!normalized.length ||
        normalized.length > MAX_REQUIREMENTS ||
        normalized.some((value) => !value ||
            value.length > 128 ||
            (0, safeString_1.containsControlCharacter)(value))) {
        throw new Error(`${label} requires between 1 and ${MAX_REQUIREMENTS} non-empty values of at most 128 characters`);
    }
    return normalized;
};
const boundedRequestString = (value, maximumLength) => typeof value === "string" &&
    value.length > 0 &&
    value.length <= maximumLength &&
    !(0, safeString_1.containsControlCharacter)(value)
    ? value
    : undefined;
const stringArray = (value) => Array.isArray(value)
    ? value.filter((item) => typeof item === "string")
    : [];
const grantedRoles = (user) => new Set([
    ...(typeof user.role === "string" ? [user.role] : []),
    ...stringArray(user.roles),
]);
const grantedClaims = (user, claim) => {
    const values = stringArray(user[claim]);
    if (claim === "scopes" && typeof user.scope === "string") {
        values.push(...user.scope.split(/\s+/).filter(Boolean));
    }
    return new Set(values);
};
const tenantIds = (user) => new Set([
    ...(typeof user.tenantId === "string" ? [user.tenantId] : []),
    ...stringArray(user.tenantIds),
]);
class AuthorizationService {
    constructor(options) {
        this.authenticate = options.authenticate;
        this.resolveTenant = options.config?.resolveTenant;
        this.audit = options.audit;
    }
    requireRole(...roles) {
        const required = normalizeRequirements(roles, "requireRole");
        return this.authorize("role", required, (user) => {
            const granted = grantedRoles(user);
            return required.some((role) => granted.has(role));
        });
    }
    requirePermission(...permissions) {
        const required = normalizeRequirements(permissions, "requirePermission");
        return this.authorize("permission", required, (user) => {
            const granted = grantedClaims(user, "permissions");
            return required.every((permission) => granted.has(permission));
        });
    }
    requireScope(...scopes) {
        const required = normalizeRequirements(scopes, "requireScope");
        return this.authorize("scope", required, (user) => {
            const granted = grantedClaims(user, "scopes");
            return required.every((scope) => granted.has(scope));
        });
    }
    requireTenant(resolveTenant = this.resolveTenant) {
        if (!resolveTenant) {
            throw new Error("requireTenant needs authorization.resolveTenant or an explicit resolver");
        }
        return this.authorize("tenant", [], () => true, resolveTenant);
    }
    authorize(kind, required, claimsAllow, tenantResolver = this.resolveTenant) {
        return async (req, res, next) => {
            const authenticated = await this.runAuthentication(req, res);
            if (!authenticated)
                return;
            const user = req.user;
            if (!user) {
                await this.deny(req, res, kind, required, undefined);
                return;
            }
            const requestedTenant = tenantResolver
                ? boundedRequestString(await tenantResolver(req), 256)
                : undefined;
            const tenantAllowed = !tenantResolver ||
                (!!requestedTenant && tenantIds(user).has(requestedTenant));
            if (!claimsAllow(user) || !tenantAllowed) {
                await this.deny(req, res, kind, required, requestedTenant, user);
                return;
            }
            return next();
        };
    }
    async runAuthentication(req, res) {
        if ((0, requestIdentity_1.isAuthenik8Authenticated)(req))
            return true;
        let authenticated = false;
        await Promise.resolve(this.authenticate(req, res, () => {
            authenticated = true;
        }));
        return authenticated;
    }
    async deny(req, res, kind, required, tenantId, user) {
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
            correlationId: boundedRequestString(req.headers["x-request-id"], 128),
            metadata: { kind, required: [...required] },
        });
        res.status(403).json(AUTHORIZATION_DENIED);
    }
}
exports.AuthorizationService = AuthorizationService;
//# sourceMappingURL=authorizationService.js.map