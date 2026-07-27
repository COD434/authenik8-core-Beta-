import { randomUUID } from "crypto";
import type { IdentityUser, OAuthIdentityAdapter } from "../types";
import {
  MAX_IDENTITY_PROVIDERS_PER_USER,
  normalizeIdentityEmail,
  validateIdentityProvider,
  validateIdentityUserId,
} from "../identityValidation";

type MemoryIdentityAdapter = OAuthIdentityAdapter & {
  reset(): void;
  dump(): IdentityUser[];
};

const users = new Map<string, IdentityUser>();
const copyUser = (user: IdentityUser): IdentityUser => structuredClone(user);

export const memoryAdapter: MemoryIdentityAdapter = {
  async findUserById(userId: string) {
    const user = users.get(validateIdentityUserId(userId));
    return user ? copyUser(user) : null;
  },

  async findUserByEmail(email: string) {
    const normalizedEmail = normalizeIdentityEmail(email);
    const user = [...users.values()].find(
      (candidate) => candidate.email === normalizedEmail,
    );
    return user ? copyUser(user) : null;
  },

  async findUserByProvider(provider: string, providerId: string) {
    const identity = validateIdentityProvider(provider, providerId);
    const user = [...users.values()].find((candidate) =>
      candidate.providers.some(
        (entry) =>
          entry.provider === identity.provider &&
          entry.providerId === identity.providerId,
      ),
    );
    return user ? copyUser(user) : null;
  },

  async createUser(data) {
    const normalizedEmail = normalizeIdentityEmail(data.email);
    const identity = validateIdentityProvider(data.provider, data.providerId);
    const existingProvider = await this.findUserByProvider(
      identity.provider,
      identity.providerId,
    );
    if (existingProvider) {
      return { status: "existing-provider", user: existingProvider };
    }

    const existingEmail = await this.findUserByEmail(normalizedEmail);
    if (existingEmail) {
      return { status: "existing-email", user: existingEmail };
    }

    const user: IdentityUser = {
      id: randomUUID(),
      email: normalizedEmail,
      providers: [
        identity,
      ],
    };
    users.set(user.id, copyUser(user));
    return { status: "created", user: copyUser(user) };
  },

  async linkProvider(userId: string, provider: string, providerId: string) {
    const validUserId = validateIdentityUserId(userId);
    const identity = validateIdentityProvider(provider, providerId);
    const providerOwner = await this.findUserByProvider(
      identity.provider,
      identity.providerId,
    );
    if (providerOwner && providerOwner.id !== validUserId) {
      throw new Error("OAuth provider is already linked");
    }

    const user = users.get(validUserId);
    if (!user) {
      throw new Error("OAuth link target user not found");
    }

    if (
      !user.providers.some(
        (entry) =>
          entry.provider === identity.provider &&
          entry.providerId === identity.providerId,
      )
    ) {
      if (user.providers.length >= MAX_IDENTITY_PROVIDERS_PER_USER) {
        throw new Error("OAuth identity provider limit exceeded");
      }
      users.set(validUserId, {
        ...user,
        providers: [...user.providers, identity],
      });
    }
  },

  reset() {
    users.clear();
  },

  dump() {
    return [...users.values()].map(copyUser);
  },
};
