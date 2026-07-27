import type { Request } from "express";
import { containsControlCharacter } from "../utility/safeString";

export const OAUTH_HTTP_TIMEOUT_MS = 10_000;
export const MAX_OAUTH_CODE_LENGTH = 4096;
export const MAX_OAUTH_JSON_RESPONSE_BYTES = 64 * 1024;

export const readBoundedJsonResponse = async (
  response: Response,
  maximumBytes = MAX_OAUTH_JSON_RESPONSE_BYTES,
): Promise<unknown> => {
  if (!Number.isSafeInteger(maximumBytes) || maximumBytes < 1) {
    throw new Error("OAuth response size limit is invalid");
  }

  // A stream is required so the decompressed body can be bounded before parse.
  if (!response.body || typeof response.body.getReader !== "function") {
    throw new Error("OAuth provider response body is unavailable");
  }

  const declaredLength = Number(response.headers?.get("content-length"));
  if (Number.isFinite(declaredLength) && declaredLength > maximumBytes) {
    await response.body.cancel();
    throw new Error("OAuth provider response exceeds the size limit");
  }

  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > maximumBytes) {
        await reader.cancel();
        throw new Error("OAuth provider response exceeds the size limit");
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }

  try {
    return JSON.parse(Buffer.concat(chunks, size).toString("utf8")) as unknown;
  } catch {
    throw new Error("OAuth provider returned invalid JSON");
  }
};

export const validateOAuthProviderConfig = (config: {
  clientId: string;
  clientSecret: string;
  redirectUri: string;
}): void => {
  if (
    typeof config.clientId !== "string" ||
    config.clientId.length === 0 ||
    config.clientId.length > 512
  ) {
    throw new Error("OAuth clientId must contain between 1 and 512 characters");
  }
  if (
    typeof config.clientSecret !== "string" ||
    Buffer.byteLength(config.clientSecret, "utf8") < 16 ||
    Buffer.byteLength(config.clientSecret, "utf8") > 4096
  ) {
    throw new Error(
      "OAuth clientSecret must contain between 16 and 4096 bytes",
    );
  }

  let redirect: URL;
  try {
    redirect = new URL(config.redirectUri);
  } catch {
    throw new Error("OAuth redirectUri must be an absolute URL");
  }
  const loopback =
    redirect.hostname === "localhost" ||
    redirect.hostname === "127.0.0.1" ||
    redirect.hostname === "[::1]";
  if (
    (redirect.protocol !== "https:" &&
      !(redirect.protocol === "http:" && loopback)) ||
    redirect.username ||
    redirect.password ||
    redirect.hash
  ) {
    throw new Error(
      "OAuth redirectUri must use HTTPS (HTTP is allowed only for loopback development)",
    );
  }
};

export const readOAuthQueryValue = (
  request: Request,
  name: "code" | "state",
): string | null => {
  const value = request.query[name];
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > MAX_OAUTH_CODE_LENGTH ||
    containsControlCharacter(value)
  ) {
    return null;
  }
  return value;
};

export const authenticatedUserId = (request: Request): string | null => {
  const userId = (request as Request & { user?: { userId?: unknown } }).user
    ?.userId;
  return typeof userId === "string" &&
    userId.length > 0 &&
    userId.length <= 256 &&
    !containsControlCharacter(userId)
    ? userId
    : null;
};
