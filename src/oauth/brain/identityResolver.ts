import { findUserByEmail, findUserByProvider, createUser, linkProvider } from "../userStore";
import { identityPolicy } from "./identityPolicy";
import { OAuthProfile } from "../types";

export async function resolveIdentity(profile: OAuthProfile) {
  const { email, provider, providerId } = profile;

  
  const byProvider = await findUserByProvider(provider, providerId);
  if (byProvider) {
    return byProvider;
  }

  
  const existingUser = await findUserByEmail(email);

  if (!existingUser) {
    return createUser({
      email,
      provider,
      providerId,
    });
  }

  

  const isVerifiedEmail = true;

  if (
    identityPolicy.autoLinkOnVerifiedEmailMatch &&
    isVerifiedEmail
  ) {
    await linkProvider(existingUser.id, provider, providerId);
    return existingUser;
  }


  return {
    type: "IDENTITY_CONFLICT",
    user: existingUser,
    message: "Account exists. Explicit linking required.",
  };
}
