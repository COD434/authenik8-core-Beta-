import { Request, Response } from "express";
import type { OAuthStateStore } from "../types";
import { OAuthCallbackResult, GoogleOAuthConfig, IdentityEngine } from "../types";
export declare function createGoogleProvider(config: GoogleOAuthConfig, stateStore: OAuthStateStore, identityEngine?: IdentityEngine): {
    redirect: (req: Request, res: Response) => Promise<void>;
    handleCallback: (req: Request) => Promise<OAuthCallbackResult>;
};
//# sourceMappingURL=google.d.ts.map