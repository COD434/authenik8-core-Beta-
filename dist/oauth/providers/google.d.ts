import { OAuthProfile, GoogleOAuthConfig } from "../types";
import { Request, Response } from "express";
import type { Redis as RedisClient } from "ioredis";
import type { IdentityEngine } from "../brain/types";
export declare function createGoogleProvider(config: GoogleOAuthConfig, redisClient: RedisClient, identityEngine: IdentityEngine): {
    redirect: (req: Request, res: Response) => Promise<void>;
    handleCallback: (req: Request) => Promise<{
        profile: OAuthProfile;
        mode: "login" | "link";
        userId: string | null;
    }>;
};
//# sourceMappingURL=google.d.ts.map