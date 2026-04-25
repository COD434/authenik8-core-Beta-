import { OAuthProfile } from "../types";

export type IdentityEngine = {
  resolveOAuth: (args: {
    profile: OAuthProfile;
    mode: "login" | "link";
    userId?: string | null;
  }) => Promise<any>;
};
