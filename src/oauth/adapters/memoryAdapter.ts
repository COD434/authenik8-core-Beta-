import { randomUUID } from "crypto";
import type { IdentityUser, OAuthIdentityAdapter } from "../identity/types";

type MemoryIdentityAdapter = OAuthIdentityAdapter & {
  reset(): void;
  dump(): IdentityUser[];
};

const users = new Map<string, IdentityUser>();

export const memoryAdapter: MemoryIdentityAdapter = {
  async findUserByEmail(email: string) {
    return [...users.values()].find((u) => u.email === email) || null;
  },

  async findUserByProvider(provider: string, providerId: string) {
    return (
      [...users.values()].find((u) =>
        u.providers.some(
          (p) => p.provider === provider && p.providerId === providerId
        )
      ) || null
    );
  },

  async createUser(data: {
    email: string;
    provider: string;
    providerId: string;
  }) {
    const user: IdentityUser = {
      id: randomUUID(),
      email: data.email,
      providers: [
        {
          provider: data.provider,
          providerId: data.providerId,
        },
      ],
    };

    users.set(user.id, user);
    return user;
  },

  async linkProvider(
    userId: string,
    provider: string,
    providerId: string
  ) {

    const user = users.get(userId);
 
    if (!user) 
      throw new Error(`User not found: ${userId}`);


    const alreadyLinked = user.providers.some(
    (p) => p.provider === provider && p.providerId === providerId
  );

  if (!alreadyLinked) {
    user.providers.push({ provider, providerId });
    users.set(userId, user);
  }
     },
  

  reset() {
    users.clear();
  },

  dump() {
    return [...users.values()];
  },
};
