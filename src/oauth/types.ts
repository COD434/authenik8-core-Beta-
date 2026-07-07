
import type { IdentityResult } from "./identity/types";

export type Provider ="google" | "github"

export type Identity = {
  provider: Provider;
  providerId: string;
  email?: string;
  verified: boolean;
};


export type User = {
  id: string;
  email: string;
  role?:string;
	providers: {
    provider: Provider;
    providerId: string;
  }[];
};

export type OAuthProfile = {
  email: string;
  name?: string;
  provider: Provider;
  providerId: string;
  email_verified: boolean | string;
};

export type OAuthCallbackResult = {
  profile: OAuthProfile;
  mode: "login" | "link";
  userId: string | null;
  identity?: IdentityResult;
  accessToken?: string;
  refreshToken?: string;
};

export type GoogleOAuthConfig = {
  clientId: string;
  clientSecret: string;
  redirectUri: string;
};
export type GitHubOAuthConfig = {
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  enterprise?:boolean
};
export type OAuthConfig = {
  google?: GoogleOAuthConfig;
  github?: GitHubOAuthConfig;
};
export type IdentityEngine = {
  resolveOAuth: (args: {
    profile: OAuthProfile;
    mode: "login" | "link";
    userId?: string | null;
  }) => Promise<any>;
};
