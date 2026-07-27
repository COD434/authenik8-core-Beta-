import type { AuditEmitter } from "../audit/types";
import type { GitHubOAuthConfig, GoogleOAuthConfig, IdentityEngine, OAuthStateStore } from "./types";
type OAuthRedisStateClient = {
    setex(key: string, seconds: number, value: string): Promise<unknown>;
    get(key: string): Promise<string | null>;
    del(key: string): Promise<unknown>;
    getdel?(key: string): Promise<string | null>;
    eval?(script: string, numberOfKeys: number, ...args: string[]): Promise<unknown>;
};
export declare const createRedisOAuthStateStore: (redisClient: OAuthRedisStateClient, keyPrefix?: string) => OAuthStateStore;
export declare function createOAuth(config: {
    google?: GoogleOAuthConfig;
    github?: GitHubOAuthConfig;
    redisClient?: OAuthRedisStateClient;
    stateStore?: OAuthStateStore;
    identityEngine?: IdentityEngine;
    audit?: AuditEmitter;
    keyPrefix?: string;
}): {
    google: {
        redirect: (req: import("express").Request, res: import("express").Response, mode?: "login" | "link") => Promise<void>;
        handleCallback: (req: import("express").Request) => Promise<import("./types").OAuthCallbackResult>;
    } | undefined;
    github: {
        redirect: (req: import("express").Request, res: import("express").Response, mode?: "login" | "link") => Promise<void>;
        handleCallback: (req: import("express").Request) => Promise<import("./types").OAuthCallbackResult>;
    } | undefined;
};
export {};
//# sourceMappingURL=core.d.ts.map