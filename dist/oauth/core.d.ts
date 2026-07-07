import { GoogleOAuthConfig, GitHubOAuthConfig, IdentityEngine } from "./types";
import type { OAuthStateStore } from "./identity/types";
type OAuthRedisStateClient = {
    setex(key: string, seconds: number, value: string): Promise<unknown>;
    get(key: string): Promise<string | null>;
    del(key: string): Promise<unknown>;
};
export declare const createRedisOAuthStateStore: (redisClient: OAuthRedisStateClient) => OAuthStateStore;
export declare function createOAuth(config: {
    google?: GoogleOAuthConfig;
    github?: GitHubOAuthConfig;
    redisClient?: OAuthRedisStateClient;
    stateStore?: OAuthStateStore;
    identityEngine?: IdentityEngine;
}): {
    google: {
        redirect: (req: import("express").Request, res: import("express").Response) => Promise<void>;
        handleCallback: (req: import("express").Request) => Promise<import("./types").OAuthCallbackResult>;
    } | undefined;
    github: {
        redirect: (req: import("express").Request, res: import("express").Response, mode?: "login" | "link") => Promise<void>;
        handleCallback: (req: import("express").Request) => Promise<import("./types").OAuthCallbackResult>;
    } | undefined;
};
export {};
//# sourceMappingURL=core.d.ts.map