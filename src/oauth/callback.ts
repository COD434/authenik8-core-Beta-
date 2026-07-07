import type {
  IdentityEngine,
  OAuthCallbackResult,
  OAuthProfile,
} from "./types";

export const finalizeOAuthCallback = async (
  profile: OAuthProfile,
  mode: "login" | "link",
  userId: string | null,
  identityEngine?: IdentityEngine
): Promise<OAuthCallbackResult> => {
  if (!identityEngine) {
    return { profile, mode, userId };
  }

  const identity = await identityEngine.resolveOAuth({ profile, mode, userId });
  if (!identity) {
    return { profile, mode, userId };
  }

  const result: OAuthCallbackResult = { profile, mode, userId, identity };

  if (
    identity.type === "EXISTING_PROVIDER_LOGIN" ||
    identity.type === "NEW_USER_CREATION"
  ) {
    result.accessToken = identity.accessToken;
    result.refreshToken = identity.refreshToken;
  }

  return result;
};
