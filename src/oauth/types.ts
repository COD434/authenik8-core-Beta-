
export type Provider ="google" | "github"
export type OAuthProfile = {
  email: string;
  name?: string;
  provider: Provider;
  providerId: string;
  email_verified: boolean | string;
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
