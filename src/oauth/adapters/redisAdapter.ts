import { randomUUID } from "crypto";
import type { Redis } from "ioredis";
import { RedisLock } from "../../utility/lockHelper";
import type { IdentityUser, OAuthIdentityAdapter } from "../types";

const PREFIX = "oauth:v1";

const normalizeEmail = (email: string) => email.trim().toLowerCase();

const userKey = (userId: string) => `${PREFIX}:user:${userId}`;
const emailKey = (email: string) => `${PREFIX}:email:${normalizeEmail(email)}`;
const providerKey = (provider: string, providerId: string) =>
  `${PREFIX}:provider:${provider}:${providerId}`;

const parseUser = (serialized: string | null): IdentityUser | null => {
  if (!serialized) {
    return null;
  }

  return JSON.parse(serialized) as IdentityUser;
};

export const createRedisIdentityAdapter = (redis: Redis): OAuthIdentityAdapter => {
  const lock = new RedisLock(redis);

  const getUserById = async (userId: string | null): Promise<IdentityUser | null> => {
    if (!userId) {
      return null;
    }

    return parseUser(await redis.get(userKey(userId)));
  };

  return {
    async findUserByEmail(email: string) {
      return getUserById(await redis.get(emailKey(email)));
    },

    async findUserByProvider(provider: string, providerId: string) {
      return getUserById(await redis.get(providerKey(provider, providerId)));
    },

    async createUser(data) {
      const normalizedEmail = normalizeEmail(data.email);
      const emailLockKey = `${PREFIX}:lock:email:${normalizedEmail}`;
      const providerIndexKey = providerKey(data.provider, data.providerId);
      const providerLockKey = `${PREFIX}:lock:provider:${data.provider}:${data.providerId}`;
      const emailLockValue = await lock.acquire(emailLockKey, 5000);

      if (!emailLockValue) {
        throw new Error("Unable to acquire OAuth email lock");
      }

      const providerLockValue = await lock.acquire(providerLockKey, 5000);

      if (!providerLockValue) {
        await lock.release(emailLockKey, emailLockValue);
        throw new Error("Unable to acquire OAuth provider lock");
      }

      try {
        const existingByEmail = await redis.get(emailKey(normalizedEmail));
        if (existingByEmail) {
          const existingUser = await getUserById(existingByEmail);
          if (existingUser) {
            return existingUser;
          }
        }

        const existingByProvider = await redis.get(providerIndexKey);
        if (existingByProvider) {
          const existingUser = await getUserById(existingByProvider);
          if (existingUser) {
            return existingUser;
          }
        }

        const user: IdentityUser = {
          id: randomUUID(),
          email: normalizedEmail,
          providers: [
            {
              provider: data.provider,
              providerId: data.providerId,
            },
          ],
        };

        await redis.multi()
          .set(userKey(user.id), JSON.stringify(user))
          .set(emailKey(normalizedEmail), user.id)
          .set(providerIndexKey, user.id)
          .exec();

        return user;
      } finally {
        await lock.release(providerLockKey, providerLockValue);
        await lock.release(emailLockKey, emailLockValue);
      }
    },

    async linkProvider(userId: string, provider: string, providerId: string) {
      const providerIndexKey = providerKey(provider, providerId);
      const providerLockKey = `${PREFIX}:lock:provider:${provider}:${providerId}`;
      const providerLockValue = await lock.acquire(providerLockKey, 5000);

      if (!providerLockValue) {
        throw new Error("Unable to acquire OAuth provider lock");
      }

      try {
        const existingProviderUserId = await redis.get(providerIndexKey);
        if (existingProviderUserId && existingProviderUserId !== userId) {
          throw new Error("Provider already linked to another user");
        }

        const existingUser = await getUserById(userId);
        if (!existingUser) {
          throw new Error(`User not found: ${userId}`);
        }

        const hasProvider = existingUser.providers.some(
          (entry) => entry.provider === provider && entry.providerId === providerId
        );

        if (!hasProvider) {
          existingUser.providers.push({ provider, providerId });
        }

        await redis.multi()
          .set(userKey(existingUser.id), JSON.stringify(existingUser))
          .set(emailKey(existingUser.email), existingUser.id)
          .set(providerIndexKey, existingUser.id)
          .exec();
      } finally {
        await lock.release(providerLockKey, providerLockValue);
      }
    },
  };
};
