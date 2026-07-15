import type { RequestHandler } from "express";
import type { JSONWebKeySet } from "jose" with { "resolution-mode": "import" };
import type { JwtPayload } from "../auth/jwtAuth";
import type { SessionMetadata } from "../auth/sessionStore";
import { TokenPayload, TokenPair } from "./tokens";
import { OAuthCallbackResult } from "../oauth/types";
import type { AgentIdentityApi } from "../agent/types";
type GitHubProvider = {
    redirect: (req: any, res: any, mode?: "login" | "link") => Promise<void>;
    handleCallback: (req: any) => Promise<OAuthCallbackResult>;
};
type GoogleProvider = {
    redirect: (req: any, res: any, mode?: "login" | "link") => Promise<void>;
    handleCallback: (req: any) => Promise<OAuthCallbackResult>;
};
export interface Authenik8Instance {
    signToken: (payload: any) => Promise<string>;
    verifyToken: (token: string) => Promise<JwtPayload | null>;
    requireAuth: RequestHandler;
    guestToken: () => Promise<string>;
    getJwks: () => JSONWebKeySet;
    listSessions: (userId: string) => Promise<SessionMetadata[]>;
    revokeSession: (userId: string, sessionId: string) => Promise<void>;
    revokeAllSessions: (userId: string) => Promise<void>;
    agent?: AgentIdentityApi;
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
    redisclient?: any;
    oauth?: {
        google?: GoogleProvider;
        github?: GitHubProvider;
    };
    issueTokens: (payload: TokenPayload) => Promise<TokenPair>;
}
export {};
//# sourceMappingURL=public.d.ts.map