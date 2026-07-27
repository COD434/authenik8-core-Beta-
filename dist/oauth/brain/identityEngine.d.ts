import type { AuditEmitter } from "../../audit/types";
import type { IdentityEngine, OAuthIdentityAdapter } from "../types";
import { type IdentityPolicy } from "./identityPolicy";
type TokenService = {
    issueTokens(payload: {
        userId: string;
        email: string;
        sessionId: string;
        role?: string;
    }): Promise<{
        accessToken: string;
        refreshToken: string;
    }>;
};
export declare function createIdentityEngine(adapter: OAuthIdentityAdapter, tokenService: TokenService, audit?: AuditEmitter, policy?: IdentityPolicy): IdentityEngine;
export {};
//# sourceMappingURL=identityEngine.d.ts.map