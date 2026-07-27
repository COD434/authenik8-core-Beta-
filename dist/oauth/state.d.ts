import type { OAuthState, OAuthStateStore } from "./types";
export declare const OAUTH_STATE_BYTES = 32;
export declare const OAUTH_STATE_TTL_SECONDS = 300;
export declare const MAX_OAUTH_STATE_RECORD_BYTES = 1024;
export declare const isValidOAuthStateToken: (state: unknown) => state is string;
export declare const isValidOAuthState: (value: unknown) => value is OAuthState;
export declare const parseOAuthState: (serialized: string) => OAuthState | null;
export declare const consumeOAuthState: (store: OAuthStateStore, state: string) => Promise<OAuthState | null>;
//# sourceMappingURL=state.d.ts.map