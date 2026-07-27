export type IdentityState =
  | "EXISTING_PROVIDER_LOGIN"
  | "EXISTING_EMAIL_CONFLICT"
  | "NEW_USER_CREATION"
  | "LINK_PROVIDER"
  | "INVALID_LINK_REQUEST"
  | "LINK_REQUIRED";

export type Provider = "google" | "github";
export type OAuthMode = "login" | "link";

export type IdentityContext = {
  email: string;
  provider: string;
  providerId: string;
  mode: OAuthMode;
  userId?: string;
};

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

export type IdentityResult =
  | {
      type: "EXISTING_PROVIDER_LOGIN";
      user: IdentityUser;
      accessToken: string;
      refreshToken: string;
    }
  | {
      type: "EXISTING_EMAIL_CONFLICT";
      email: string;
      user: IdentityUser;
      message: string;
    }
  | {
      type: "NEW_USER_CREATION";
      user: IdentityUser;
      accessToken: string;
      refreshToken: string;
    }
  | {
      type: "LINK_PROVIDER";
      success: true;
      user: IdentityUser;
    }
  | {
      type: "INVALID_LINK_REQUEST";
      message: string;
    }
  | {
      type: "LINK_REQUIRED";
      message: string;
      email: string;
      provider: string;
    };

export type IdentityUserCreationResult =
  | { status: "created"; user: IdentityUser }
  | { status: "existing-provider"; user: IdentityUser }
  | { status: "existing-email"; user: IdentityUser };

export interface OAuthIdentityAdapter {
  findUserById(userId: string): Promise<IdentityUser | null>;
  findUserByEmail(email: string): Promise<IdentityUser | null>;
  findUserByProvider(
    provider: string,
    providerId: string,
  ): Promise<IdentityUser | null>;
  createUser(data: {
    email: string;
    provider: string;
    providerId: string;
  }): Promise<IdentityUserCreationResult>;
  linkProvider(
    userId: string,
    provider: string,
    providerId: string,
  ): Promise<void>;
}

export type OAuthState = {
  userId: string | null;
  mode: OAuthMode;
};

export interface OAuthStateStore {
  set(state: string, value: OAuthState, ttlSeconds: number): Promise<void>;
  /** Atomically reads and removes a one-time OAuth state value. */
  take(state: string): Promise<OAuthState | null>;
  /** Optional diagnostic read; authentication flows never use it. */
  get?(state: string): Promise<OAuthState | null>;
  /** Optional administrative deletion; authentication flows never use it. */
  del?(state: string): Promise<void>;
}

export type Identity = {
  provider: Provider;
  providerId: string;
  email?: string;
  verified: boolean;
};

/** @deprecated Use `IdentityUser`. */
export type User = {
  id: string;
  email: string;
  role?: string;
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
  email_verified: boolean;
};

export type OAuthCallbackResult = {
  profile: OAuthProfile;
  mode: OAuthMode;
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
  /**
   * @deprecated This boolean never provided enough information to validate
   * enterprise endpoints and is rejected. Use a dedicated trusted adapter.
   */
  enterprise?: boolean;
};

export type OAuthConfig = {
  google?: GoogleOAuthConfig;
  github?: GitHubOAuthConfig;
  /**
   * Optional application-owned one-time state store. `take()` must atomically
   * read and remove a value. Redis-backed state is used when omitted.
   */
  stateStore?: OAuthStateStore;
};

export type IdentityEngine = {
  resolveOAuth: (args: {
    profile: OAuthProfile;
    mode: OAuthMode;
    userId?: string | null;
  }) => Promise<IdentityResult>;
};
