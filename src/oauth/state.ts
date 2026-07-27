import type { OAuthState, OAuthStateStore } from "./types";
import { containsControlCharacter } from "../utility/safeString";

export const OAUTH_STATE_BYTES = 32;
export const OAUTH_STATE_TTL_SECONDS = 300;
export const MAX_OAUTH_STATE_RECORD_BYTES = 1024;
const OAUTH_STATE_PATTERN = /^[a-f0-9]{64}$/;

export const isValidOAuthStateToken = (state: unknown): state is string =>
  typeof state === "string" && OAUTH_STATE_PATTERN.test(state);

export const isValidOAuthState = (value: unknown): value is OAuthState => {
  if (!value || typeof value !== "object") return false;
  try {
    const candidate = value as Partial<OAuthState>;
    const keys = Object.keys(candidate).sort();
    if (
      keys.length !== 2 ||
      keys[0] !== "mode" ||
      keys[1] !== "userId"
    ) {
      return false;
    }
    return (
      (candidate.mode === "login" && candidate.userId === null) ||
      (candidate.mode === "link" &&
        typeof candidate.userId === "string" &&
        candidate.userId.length > 0 &&
        candidate.userId.length <= 256 &&
        !containsControlCharacter(candidate.userId))
    );
  } catch {
    return false;
  }
};

export const parseOAuthState = (serialized: string): OAuthState | null => {
  if (
    typeof serialized !== "string" ||
    Buffer.byteLength(serialized, "utf8") > MAX_OAUTH_STATE_RECORD_BYTES
  ) {
    return null;
  }
  try {
    const value: unknown = JSON.parse(serialized);
    return isValidOAuthState(value) ? value : null;
  } catch {
    return null;
  }
};

export const consumeOAuthState = async (
  store: OAuthStateStore,
  state: string,
): Promise<OAuthState | null> => {
  if (!isValidOAuthStateToken(state)) return null;
  const value = await store.take(state);
  return isValidOAuthState(value) ? value : null;
};
