import { createGoogleProvider } from "./google";
import { GoogleOAuthConfig } from "./types";

export function createOAuth(config:{google?: GoogleOAuthConfig;} ) {
  return {
    google: config.google
      ? createGoogleProvider(config.google)
      : undefined,
  };
}
