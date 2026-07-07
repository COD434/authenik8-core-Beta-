import type { IdentityEngine, OAuthCallbackResult, OAuthProfile } from "./types";
export declare const finalizeOAuthCallback: (profile: OAuthProfile, mode: "login" | "link", userId: string | null, identityEngine?: IdentityEngine) => Promise<OAuthCallbackResult>;
//# sourceMappingURL=callback.d.ts.map