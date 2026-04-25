import { Request, Response } from "express";
import { OAuthProfile } from "../types";
import type { Redis as RedisClient } from "ioredis";
import { GitHubOAuthConfig } from "../types";
import type { IdentityEngine } from "../brain/types";
export declare function createGitHubProvider(config: GitHubOAuthConfig, redisClient: RedisClient, identityEngine: IdentityEngine): {
    redirect: (req: Request, res: Response, mode?: "login" | "link") => Promise<void>;
    handleCallback: (req: Request) => Promise<{
        profile: OAuthProfile;
        mode: "login" | "link";
        userId: string | null;
    }>;
};
//# sourceMappingURL=github.d.ts.map