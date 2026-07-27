import { createHash } from "crypto";

const MAX_PREFIX_LENGTH = 128;
const PREFIX_PATTERN = /^[A-Za-z0-9][A-Za-z0-9:._-]*$/;

export const validateRedisKeyPrefix = (prefix: string): string => {
  const normalized = prefix.trim();
  if (
    !normalized ||
    normalized.length > MAX_PREFIX_LENGTH ||
    !PREFIX_PATTERN.test(normalized) ||
    normalized.endsWith(":")
  ) {
    throw new Error(
      "redisKeyPrefix must be 1-128 letters, numbers, colons, dots, underscores, or hyphens and may not end with a colon",
    );
  }
  return normalized;
};

export const resolveRedisKeyPrefix = (
  configuredPrefix: string | undefined,
  issuer: string,
  audience: string | string[],
): string => {
  if (configuredPrefix !== undefined) {
    return validateRedisKeyPrefix(configuredPrefix);
  }

  const audiences = Array.isArray(audience) ? audience : [audience];
  const securityDomain = createHash("sha256")
    .update(issuer)
    .update("\0")
    .update(audiences.join("\0"))
    .digest("base64url")
    .slice(0, 22);
  return `authenik8:v2:${securityDomain}`;
};

export const redisKey = (
  prefix: string,
  ...parts: readonly string[]
): string => [prefix, ...parts].join(":");
