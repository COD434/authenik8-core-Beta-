import { Request, Response } from "express";
import type { OAuthStateStore } from "../types";
import type { AuditEmitter } from "../../audit/types";
import { GitHubOAuthConfig, IdentityEngine, OAuthCallbackResult } from "../types";
export declare function createGitHubProvider(config: GitHubOAuthConfig, stateStore: OAuthStateStore, identityEngine?: IdentityEngine, audit?: AuditEmitter): {
    redirect: (req: Request, res: Response, mode?: "login" | "link") => Promise<void>;
    handleCallback: (req: Request) => Promise<OAuthCallbackResult>;
};
//# sourceMappingURL=github.d.ts.map