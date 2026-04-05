import { GoogleOAuthConfig } from "./types";
export declare function createOAuth(config: {
    google?: GoogleOAuthConfig;
}): {
    google: {
        redirect: (req: import("express").Request, res: import("express").Response) => void;
        handleCallback: (req: import("express").Request) => Promise<{
            profile: import("./types").OAuthProfile;
        }>;
    } | undefined;
};
//# sourceMappingURL=core.d.ts.map