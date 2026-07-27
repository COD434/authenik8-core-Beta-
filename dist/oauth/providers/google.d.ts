import { Request, Response } from "express";
import type { OAuthStateStore } from "../types";
import type { AuditEmitter } from "../../audit/types";
import { OAuthCallbackResult, GoogleOAuthConfig, IdentityEngine } from "../types";
export declare function createGoogleProvider(config: GoogleOAuthConfig, stateStore: OAuthStateStore, identityEngine?: IdentityEngine, audit?: AuditEmitter): {
    redirect: (req: Request, res: Response, mode?: "login" | "link") => Promise<void>;
    handleCallback: (req: Request) => Promise<OAuthCallbackResult>;
};
//# sourceMappingURL=google.d.ts.map