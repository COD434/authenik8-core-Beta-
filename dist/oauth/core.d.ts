import { GoogleOAuthConfig, GitHubOAuthConfig } from "./types";
import type { Redis as RedisClient } from "ioredis";
import { OAuthProfile } from "./types";
import type { IdentityEngine } from "./brain/types";
export declare function createOAuth(config: {
    google?: GoogleOAuthConfig;
    github?: GitHubOAuthConfig;
    redisClient: RedisClient;
    identityEngine: IdentityEngine;
}): {
    google: {
        redirect: (req: import("express").Request, res: import("express").Response) => Promise<void>;
        handleCallback: (req: import("express").Request) => Promise<{
            profile: OAuthProfile;
            mode: "login" | "link";
            userId: string | null;
        }>;
    } | undefined;
    github: {
        redirect: (req: import("express").Request, res: import("express").Response, mode?: "login" | "link") => Promise<void>;
        handleCallback: (req: import("express").Request) => Promise<{
            profile: OAuthProfile;
            mode: "login" | "link";
            userId: string | null;
        }>;
    } | undefined;
};
//# sourceMappingURL=core.d.ts.map