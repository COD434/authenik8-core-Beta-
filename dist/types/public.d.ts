import { TokenPayload, TokenPair } from "./tokens";
import { OAuthProfile } from "../oauth/types";
type GitHubProvider = {
    redirect: (req: any, res: any, mode?: "login" | "link") => Promise<void>;
    handleCallback: (req: any) => Promise<{
        profile: OAuthProfile;
        mode: "login" | "link";
        userId: string | null;
    }>;
};
type GoogleProvider = {
    redirect: (req: any, res: any, mode?: "login" | "link") => Promise<void>;
    handleCallback: (req: any) => Promise<{
        profile: OAuthProfile;
        mode: "login" | "link";
        userId: string | null;
    }>;
};
export interface Authenik8Instance {
    signToken: (payload: any) => string;
    verifyToken: (token: string) => any;
    guestToken: () => string;
    refreshToken: (token: string) => Promise<any>;
    generateRefreshToken: (payload: any) => Promise<string>;
    rateLimit: any;
    ipWhitelist: any;
    helmet: any;
    addIP: (ip: string) => Promise<void>;
    removeIP: (ip: string) => Promise<void>;
    listIPs: () => Promise<string[]>;
    requireAdmin: any;
    incognito: any;
    redis?: any;
    oauth?: {
        google?: GoogleProvider;
        github?: GitHubProvider;
    };
    issueTokens: (payload: TokenPayload) => Promise<TokenPair>;
    issueTokensFromProfile: (profile: OAuthProfile) => Promise<TokenPair>;
}
export {};
//# sourceMappingURL=public.d.ts.map