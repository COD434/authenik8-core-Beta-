import { OAuthProfile, GoogleOAuthConfig } from "./types";
import { Request, Response } from "express";
export declare function createGoogleProvider(config: GoogleOAuthConfig): {
    redirect: (req: Request, res: Response) => void;
    handleCallback: (req: Request) => Promise<{
        profile: OAuthProfile;
    }>;
};
//# sourceMappingURL=google.d.ts.map