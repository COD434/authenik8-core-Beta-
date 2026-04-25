import crypto from "crypto";
import { OAuthProfile } from "./types";


export type Provider = "google" | "github";

export type User = {
  id: string;
  email: string;
  role?:string;
  providers: {
    provider: Provider;
    providerId: string;
  }[];
};


const users: User[] = [];

export async function findUserByEmail(email: string): Promise<User | undefined> {
  return users.find((u) => u.email === email);
}

export async function findUserByProvider(
  provider: Provider,
  providerId: string
): Promise<User | undefined> {
  return users.find((u) =>
    u.providers.some(
      (p) => p.provider === provider && p.providerId === providerId
    )
  );
}

export async function createUser(data: {
  email: string;
  provider: Provider;
  providerId: string;
}): Promise<User> {
  const newUser: User = {
    id: crypto.randomUUID(),
    email: data.email,
    providers: [
      {
        provider: data.provider,
        providerId: data.providerId,
      },
    ],
  };

  users.push(newUser);
  return newUser;
}

export async function linkProvider(
  userId: string,
  provider: Provider,
  providerId: string
): Promise<void> {
  const user = users.find((u) => u.id === userId);

  if (!user) return;

  const alreadyLinked = user.providers.some(
    (p) => p.provider === provider
  );

  if (!alreadyLinked) {
    user.providers.push({ provider, providerId });
  }
}

 
