import { TokenPayload, TokenPair } from "./tokens";
import { OAuthCallbackResult } from "../oauth/types";

 type GitHubProvider = {
  redirect: (req:any, res: any,mode?: "login" | "link") =>Promise<void>;
  handleCallback: (req: any) => Promise<OAuthCallbackResult>;
};

type GoogleProvider = {
  redirect: (req: any, res: any,mode?: "login" | "link") => Promise<void>;
  handleCallback: (req: any) => Promise<OAuthCallbackResult>;
};


export interface Authenik8Instance {
  signToken: (payload: any) =>Promise<string>;
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

  redisclient?: any;
  oauth?: {
    google?: GoogleProvider;
    github?: GitHubProvider;
  };
  
  issueTokens: (payload: TokenPayload) => Promise<TokenPair>;
}
