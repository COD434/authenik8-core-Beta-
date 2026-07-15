
//import type { IdentityResult } from "./identity/types";


export type IdentityState =
  | "EXISTING_PROVIDER_LOGIN"
  | "EXISTING_EMAIL_CONFLICT"
  | "NEW_USER_CREATION"
  | "LINK_PROVIDER"
  | "INVALID_LINK_REQUEST"
  | "LINK_REQUIRED"

  export type IdentityContext = {
  email: string;
  provider: string;
  providerId: string;

  mode: "login" | "link";
  userId?: string;
};

 export type IdentityResult =
  | {
      type: "EXISTING_PROVIDER_LOGIN";
      user: any;
      accessToken: string;
      refreshToken: string;
    }
  | {
      type: "EXISTING_EMAIL_CONFLICT";
      email: string;
      user:any
      message: string;
    }
  | {
      type: "NEW_USER_CREATION";
      user: any;
      accessToken: string;
      refreshToken: string;
    }
  | {
      type: "LINK_PROVIDER";
      success: true;
      user:any;
    }
  | {
      type: "INVALID_LINK_REQUEST";
      message: string;
    }
  | {
	  type: "LINK_REQUIRED";
	  message:string;
	  email:string;
	  provider:string;
  }

export type IdentityProviderRecord = {
  provider: string;
  providerId: string;
};

export type IdentityUser = {
  id: string;
  email: string;
  role?: string;
  providers: IdentityProviderRecord[];
};

export interface OAuthIdentityAdapter {
  findUserByEmail(email: string): Promise<IdentityUser | null>;
  findUserByProvider(provider: string, providerId: string): Promise<IdentityUser | null>;
  createUser(data: {
    email: string;
    provider: string;
    providerId: string;
  }): Promise<IdentityUser>;
  linkProvider(userId: string, provider: string, providerId: string): Promise<void>;
}

export type OAuthMode = "login" | "link";

export type OAuthState = {
  userId: string | null;
  mode: OAuthMode;
};

export interface OAuthStateStore {
  set(state: string, value: OAuthState, ttlSeconds: number): Promise<void>;
  get(state: string): Promise<OAuthState | null>;
  del(state: string): Promise<void>;
}




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
