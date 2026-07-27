import { createGoogleProvider } from "./providers/google";
import { createGitHubProvider } from "./providers/github";
import type { AuditEmitter } from "../audit/types";
import { validateRedisKeyPrefix } from "../redis/keyNamespace";
import type {
  GitHubOAuthConfig,
  GoogleOAuthConfig,
  IdentityEngine,
  OAuthState,
  OAuthStateStore,
} from "./types";
import {
  isValidOAuthStateToken,
  isValidOAuthState,
  OAUTH_STATE_TTL_SECONDS,
  parseOAuthState,
} from "./state";

type OAuthRedisStateClient = {
  setex(key: string, seconds: number, value: string): Promise<unknown>;
  get(key: string): Promise<string | null>;
  del(key: string): Promise<unknown>;
  getdel?(key: string): Promise<string | null>;
  eval?(
    script: string,
    numberOfKeys: number,
    ...args: string[]
  ): Promise<unknown>;
};

const TAKE_STATE_SCRIPT = `
local value = redis.call("GET", KEYS[1])
if value then
  redis.call("DEL", KEYS[1])
end
return value
`;

const stateKey = (keyPrefix: string, state: string) =>
  `${keyPrefix}:state:${state}`;

export const createRedisOAuthStateStore = (
  redisClient: OAuthRedisStateClient,
  keyPrefix = "oauth",
): OAuthStateStore => {
  if (!redisClient.getdel && !redisClient.eval) {
    throw new Error("OAuth Redis state requires atomic GETDEL or EVAL support");
  }
  const prefix = validateRedisKeyPrefix(keyPrefix);

  return {
    async set(state: string, value: OAuthState, ttlSeconds: number) {
      if (!isValidOAuthStateToken(state)) {
        throw new Error(
          "OAuth state must be a 256-bit lower-case hexadecimal value",
        );
      }
      if (!isValidOAuthState(value)) {
        throw new Error("OAuth state payload is invalid");
      }
      if (
        !Number.isSafeInteger(ttlSeconds) ||
        ttlSeconds <= 0 ||
        ttlSeconds > OAUTH_STATE_TTL_SECONDS
      ) {
        throw new Error(
          `OAuth state TTL must be between 1 and ${OAUTH_STATE_TTL_SECONDS} seconds`,
        );
      }
      await redisClient.setex(
        stateKey(prefix, state),
        ttlSeconds,
        JSON.stringify(value),
      );
    },

    async get(state: string) {
      if (!isValidOAuthStateToken(state)) return null;
      const stored = await redisClient.get(stateKey(prefix, state));
      return stored ? parseOAuthState(stored) : null;
    },

    async del(state: string) {
      if (!isValidOAuthStateToken(state)) return;
      await redisClient.del(stateKey(prefix, state));
    },

    async take(state: string) {
      if (!isValidOAuthStateToken(state)) return null;
      const key = stateKey(prefix, state);
      const stored = redisClient.getdel
        ? await redisClient.getdel(key)
        : ((await redisClient.eval!(
            TAKE_STATE_SCRIPT,
            1,
            key,
          )) as string | null);
      return stored ? parseOAuthState(stored) : null;
    },
  };
};

export function createOAuth(config: {
  google?: GoogleOAuthConfig;
  github?: GitHubOAuthConfig;
  redisClient?: OAuthRedisStateClient;
  stateStore?: OAuthStateStore;
  identityEngine?: IdentityEngine;
  audit?: AuditEmitter;
  keyPrefix?: string;
}) {
  const stateStore =
    config.stateStore ??
    (config.redisClient
      ? createRedisOAuthStateStore(config.redisClient, config.keyPrefix)
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
  if (
    typeof stateStore.set !== "function" ||
    typeof stateStore.take !== "function"
  ) {
    throw new Error("OAuth stateStore must implement set() and atomic take()");
  }

  return {
    google: config.google
      ? createGoogleProvider(
          config.google,
          stateStore,
          config.identityEngine,
          config.audit,
        )
      : undefined,
    github: config.github
      ? createGitHubProvider(
          config.github,
          stateStore,
          config.identityEngine,
          config.audit,
        )
      : undefined,
  };
}
