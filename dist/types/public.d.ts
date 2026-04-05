import { OAuthProfile } from "../oauth/providers/types";
type GoogleProvider = {
    redirect: (req: any, res: any) => void;
    handleCallback: (req: any) => Promise<{
        profile: OAuthProfile;
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
    };
}
export {};
//# sourceMappingURL=public.d.ts.map