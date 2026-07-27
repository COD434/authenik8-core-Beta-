import { containsControlCharacter } from "../utility/safeString";
import type { IdentityUser } from "./types";

export const MAX_IDENTITY_EMAIL_LENGTH = 254;
export const MAX_IDENTITY_USER_ID_LENGTH = 256;
export const MAX_IDENTITY_PROVIDER_ID_LENGTH = 512;
export const MAX_IDENTITY_PROVIDERS_PER_USER = 32;
export const MAX_IDENTITY_ROLE_LENGTH = 128;

const PROVIDER_PATTERN = /^[a-z][a-z0-9._-]{0,63}$/;

export const normalizeIdentityEmail = (value: unknown): string => {
  if (typeof value !== "string") {
    throw new Error("OAuth profile has an invalid email");
  }

  const email = value.trim().toLowerCase();
  const at = email.indexOf("@");
  if (
    email.length === 0 ||
    email.length > MAX_IDENTITY_EMAIL_LENGTH ||
    containsControlCharacter(email) ||
    at <= 0 ||
    at !== email.lastIndexOf("@") ||
    at === email.length - 1
  ) {
    throw new Error("OAuth profile has an invalid email");
  }
  return email;
};

export const validateIdentityProvider = (
  providerValue: unknown,
  providerIdValue: unknown,
): { provider: string; providerId: string } => {
  if (
    typeof providerValue !== "string" ||
    !PROVIDER_PATTERN.test(providerValue)
  ) {
    throw new Error("OAuth identity provider is invalid");
  }
  if (
    typeof providerIdValue !== "string" ||
    providerIdValue.length === 0 ||
    providerIdValue.length > MAX_IDENTITY_PROVIDER_ID_LENGTH ||
    containsControlCharacter(providerIdValue)
  ) {
    throw new Error("OAuth providerId is invalid");
  }
  return { provider: providerValue, providerId: providerIdValue };
};

export const validateIdentityUserId = (value: unknown): string => {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > MAX_IDENTITY_USER_ID_LENGTH ||
    containsControlCharacter(value)
  ) {
    throw new Error("OAuth identity user is invalid");
  }
  return value;
};

export const validateIdentityUser = (value: unknown): IdentityUser => {
  if (!value || typeof value !== "object") {
    throw new Error("OAuth identity adapter returned an invalid user");
  }
  const candidate = value as Partial<IdentityUser>;
  const id = validateIdentityUserId(candidate.id);
  const email = normalizeIdentityEmail(candidate.email);
  if (email !== candidate.email) {
    throw new Error("OAuth identity user email must be normalized");
  }
  if (
    candidate.role !== undefined &&
    (typeof candidate.role !== "string" ||
      candidate.role.length === 0 ||
      candidate.role.length > MAX_IDENTITY_ROLE_LENGTH ||
      containsControlCharacter(candidate.role))
  ) {
    throw new Error("OAuth identity user role is invalid");
  }
  if (
    !Array.isArray(candidate.providers) ||
    candidate.providers.length > MAX_IDENTITY_PROVIDERS_PER_USER
  ) {
    throw new Error("OAuth identity user providers are invalid");
  }

  const providers = candidate.providers.map((entry) => {
    if (!entry || typeof entry !== "object") {
      throw new Error("OAuth identity user provider is invalid");
    }
    return validateIdentityProvider(entry.provider, entry.providerId);
  });
  if (
    new Set(
      providers.map(
        (entry) => `${entry.provider}\0${entry.providerId}`,
      ),
    ).size !== providers.length
  ) {
    throw new Error("OAuth identity user contains duplicate providers");
  }

  return {
    id,
    email,
    ...(candidate.role !== undefined ? { role: candidate.role } : {}),
    providers,
  };
};
