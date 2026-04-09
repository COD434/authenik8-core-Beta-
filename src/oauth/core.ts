import { createGoogleProvider } from "./providers/google";
import { GoogleOAuthConfig,GitHubOAuthConfig } from "./types";
import type { Redis as RedisClient } from "ioredis";
import { OAuthProfile } from "./types";
import type { IdentityEngine } from "./brain/types";

import { createGitHubProvider } from "./providers/github";

export function createOAuth(config:{google?: GoogleOAuthConfig;github?:GitHubOAuthConfig;redisClient:RedisClient;identityEngine:IdentityEngine} ) {
  return {
    google: config.google
      ? createGoogleProvider(config.google,config.redisClient,config.identityEngine)
      : undefined,
      github: config.github
    ? createGitHubProvider(config.github,config.redisClient,config.identityEngine)
    : undefined,
  };
}

