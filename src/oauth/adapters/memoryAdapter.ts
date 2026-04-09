import { randomUUID } from "crypto";

type Provider = {
  provider: string;
  providerId: string;
};

type User = {
  id: string;
  email: string;
  providers: Provider[];
};

// 🔥 SINGLE SOURCE OF TRUTH (REAL MEMORY STORE)
const users = new Map<string, User>();

export const memoryAdapter = {
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
    const user: User = {
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

    if (!user) {
      throw new Error(`User not found: ${userId}`);
    }

    user.providers.push({ provider, providerId });
    users.set(userId, user);
  },

  reset() {
    users.clear();
  },

  dump() {
    return [...users.values()];
  },
};
