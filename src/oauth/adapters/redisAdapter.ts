import { createHash, randomUUID } from "crypto";
import type { Redis } from "ioredis";
import { validateRedisKeyPrefix } from "../../redis/keyNamespace";
import type {
  IdentityUser,
  IdentityUserCreationResult,
  OAuthIdentityAdapter,
} from "../types";
import {
  MAX_IDENTITY_PROVIDERS_PER_USER,
  normalizeIdentityEmail,
  validateIdentityProvider,
  validateIdentityUser,
  validateIdentityUserId,
} from "../identityValidation";

const CREATE_USER_SCRIPT = `
local provider_user_id = redis.call("GET", KEYS[3])
if provider_user_id then
  return { "existing-provider", provider_user_id }
end

local email_user_id = redis.call("GET", KEYS[2])
if email_user_id then
  return { "existing-email", email_user_id }
end

redis.call("SET", KEYS[1], ARGV[2])
redis.call("SET", KEYS[2], ARGV[1])
redis.call("SET", KEYS[3], ARGV[1])
return { "created", ARGV[1] }
`;

const LINK_PROVIDER_SCRIPT = `
local provider_user_id = redis.call("GET", KEYS[1])
if provider_user_id and provider_user_id ~= ARGV[1] then
  return "provider-conflict"
end

local email_user_id = redis.call("GET", KEYS[3])
if email_user_id and email_user_id ~= ARGV[1] then
  return "email-conflict"
end

local current_user = redis.call("GET", KEYS[2])
if not current_user then
  return "user-missing"
end
if current_user ~= ARGV[2] then
  return "stale"
end

redis.call("SET", KEYS[2], ARGV[3])
redis.call("SET", KEYS[3], ARGV[1])
redis.call("SET", KEYS[1], ARGV[1])
return "linked"
`;

const MAX_LINK_CAS_ATTEMPTS = 5;
const MAX_SERIALIZED_USER_BYTES = 32 * 1024;

const digest = (value: string): string =>
  createHash("sha256").update(value).digest("base64url");

const parseUser = (serialized: string | null): IdentityUser | null => {
  if (!serialized) return null;
  if (Buffer.byteLength(serialized, "utf8") > MAX_SERIALIZED_USER_BYTES) {
    throw new Error("OAuth identity store user record exceeds the size limit");
  }

  let value: unknown;
  try {
    value = JSON.parse(serialized);
  } catch {
    throw new Error("OAuth identity store contains invalid JSON");
  }
  try {
    return validateIdentityUser(value);
  } catch {
    throw new Error("OAuth identity store contains an invalid user record");
  }
};

const creationResult = (
  value: unknown,
): { status: IdentityUserCreationResult["status"]; userId: string } => {
  if (
    !Array.isArray(value) ||
    value.length !== 2 ||
    (value[0] !== "created" &&
      value[0] !== "existing-provider" &&
      value[0] !== "existing-email") ||
    typeof value[1] !== "string"
  ) {
    throw new Error("OAuth identity transaction returned an invalid result");
  }
  return { status: value[0], userId: value[1] };
};

export const createRedisIdentityAdapter = (
  redis: Redis,
  prefix = "oauth:v1",
): OAuthIdentityAdapter => {
  // The hash tag keeps every identity index in one Redis Cluster slot so the
  // atomic Lua transactions remain valid on both standalone and clustered Redis.
  const identityPrefix = `${validateRedisKeyPrefix(prefix)}:{identity}`;
  const userKey = (userId: string) =>
    `${identityPrefix}:user:${digest(userId)}`;
  const emailKey = (email: string) =>
    `${identityPrefix}:email:${digest(normalizeIdentityEmail(email))}`;
  const providerKey = (provider: string, providerId: string) =>
    `${identityPrefix}:provider:${digest(`${provider}\0${providerId}`)}`;

  const getUserById = async (
    userId: string | null,
  ): Promise<IdentityUser | null> => {
    if (!userId) return null;
    const user = parseUser(await redis.get(userKey(userId)));
    if (user && user.id !== userId) {
      throw new Error("OAuth identity index integrity check failed");
    }
    return user;
  };

  return {
    findUserById(userId: string) {
      return getUserById(validateIdentityUserId(userId));
    },

    async findUserByEmail(email: string) {
      const normalizedEmail = normalizeIdentityEmail(email);
      const user = await getUserById(
        await redis.get(emailKey(normalizedEmail)),
      );
      if (user && user.email !== normalizedEmail) {
        throw new Error("OAuth email index integrity check failed");
      }
      return user;
    },

    async findUserByProvider(provider: string, providerId: string) {
      const identity = validateIdentityProvider(provider, providerId);
      const user = await getUserById(
        await redis.get(providerKey(identity.provider, identity.providerId)),
      );
      if (
        user &&
        !user.providers.some(
          (entry) =>
            entry.provider === identity.provider &&
            entry.providerId === identity.providerId,
        )
      ) {
        throw new Error("OAuth provider index integrity check failed");
      }
      return user;
    },

    async createUser(data) {
      const normalizedEmail = normalizeIdentityEmail(data.email);
      const { provider, providerId } = validateIdentityProvider(
        data.provider,
        data.providerId,
      );
      const user: IdentityUser = {
        id: randomUUID(),
        email: normalizedEmail,
        providers: [
          {
            provider,
            providerId,
          },
        ],
      };

      const transaction = creationResult(
        await redis.eval(
          CREATE_USER_SCRIPT,
          3,
          userKey(user.id),
          emailKey(normalizedEmail),
          providerKey(provider, providerId),
          user.id,
          JSON.stringify(user),
        ),
      );
      const resolvedUser =
        transaction.status === "created"
          ? user
          : await getUserById(transaction.userId);
      if (!resolvedUser) {
        throw new Error("OAuth identity index points to a missing user");
      }
      if (
        transaction.status === "existing-provider" &&
        !resolvedUser.providers.some(
          (entry) =>
            entry.provider === provider &&
            entry.providerId === providerId,
        )
      ) {
        throw new Error("OAuth provider index integrity check failed");
      }
      if (
        transaction.status === "existing-email" &&
        resolvedUser.email !== normalizedEmail
      ) {
        throw new Error("OAuth email index integrity check failed");
      }

      return { status: transaction.status, user: resolvedUser };
    },

    async linkProvider(userId: string, provider: string, providerId: string) {
      validateIdentityUserId(userId);
      const identity = validateIdentityProvider(provider, providerId);
      for (let attempt = 0; attempt < MAX_LINK_CAS_ATTEMPTS; attempt += 1) {
        const serialized = await redis.get(userKey(userId));
        const existingUser = parseUser(serialized);
        if (!serialized || !existingUser || existingUser.id !== userId) {
          throw new Error("OAuth link target user not found");
        }

        const hasProvider = existingUser.providers.some(
          (entry) =>
            entry.provider === identity.provider &&
            entry.providerId === identity.providerId,
        );
        if (
          !hasProvider &&
          existingUser.providers.length >= MAX_IDENTITY_PROVIDERS_PER_USER
        ) {
          throw new Error("OAuth identity provider limit exceeded");
        }
        const updatedUser: IdentityUser = hasProvider
          ? existingUser
          : {
              ...existingUser,
              providers: [
                ...existingUser.providers,
                identity,
              ],
            };

        const result = await redis.eval(
          LINK_PROVIDER_SCRIPT,
          3,
          providerKey(identity.provider, identity.providerId),
          userKey(userId),
          emailKey(existingUser.email),
          userId,
          serialized,
          JSON.stringify(updatedUser),
        );

        if (result === "linked") return;
        if (result === "provider-conflict") {
          throw new Error("OAuth provider is already linked");
        }
        if (result === "email-conflict") {
          throw new Error("OAuth email index conflict");
        }
        if (result === "user-missing") {
          throw new Error("OAuth link target user not found");
        }
        if (result !== "stale") {
          throw new Error("OAuth provider link transaction failed");
        }
      }

      throw new Error("OAuth provider link contention limit exceeded");
    },
  };
};
