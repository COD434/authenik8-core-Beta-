import { createGoogleProvider } from "./providers/google";
import { GoogleOAuthConfig, GitHubOAuthConfig, IdentityEngine } from "./types";
import type { OAuthState, OAuthStateStore } from "./types";
import { createGitHubProvider } from "./providers/github";

type OAuthRedisStateClient = {
  setex(key: string, seconds: number, value: string): Promise<unknown>;
  get(key: string): Promise<string | null>;
  del(key: string): Promise<unknown>;
};



const stateKey = (state: string) => `oauth:state:${state}`;

export const createRedisOAuthStateStore = (
  redisClient: OAuthRedisStateClient
): OAuthStateStore => ({
  async set(state: string, value: OAuthState, ttlSeconds: number) {
    await redisClient.setex(stateKey(state), ttlSeconds, JSON.stringify(value));
  },

  async get(state: string) {
    const stored = await redisClient.get(stateKey(state));
    return stored ? (JSON.parse(stored) as OAuthState) : null;
  },

  async del(state: string) {
    await redisClient.del(stateKey(state));
  },
});

export function createOAuth(config: {
  google?: GoogleOAuthConfig;
  github?: GitHubOAuthConfig;
  redisClient?: OAuthRedisStateClient;
  stateStore?: OAuthStateStore;
  identityEngine?: IdentityEngine;
}) {
  const stateStore =
    config.stateStore ??
    (config.redisClient
      ? createRedisOAuthStateStore(config.redisClient)
      : undefined);

  if (!config.google && !config.github) {
    return {
      google: undefined,
      github: undefined,
    };
  }

  if (!stateStore) {
    throw new Error("OAuth requires a stateStore or redisClient");
  }

  return {
    google: config.google
      ? createGoogleProvider(config.google, stateStore, config.identityEngine)
      : undefined,
    github: config.github
      ? createGitHubProvider(config.github, stateStore, config.identityEngine)
      : undefined,
  };
}
