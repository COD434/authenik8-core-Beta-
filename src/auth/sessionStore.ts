import {
  tokenFingerprint,
  tokenFingerprintMatches,
} from "./tokenFingerprint";
import { validateRedisKeyPrefix } from "../redis/keyNamespace";
import { containsControlCharacter } from "../utility/safeString";

export interface SessionMetadata {
  sessionId: string;
  device: string;
  ip: string;
  createdAt: number;
}

export type StoredSession = SessionMetadata & {
  tokenHash?: string;
  /** Read-only migration support for sessions written before token hashing. */
  token?: string;
};

export type SessionRedisClient = {
  hget?: (key: string, field: string) => Promise<string | null>;
  hgetall?: (key: string) => Promise<Record<string, string> | null>;
  hset?: (key: string, field: string, value: string) => Promise<unknown>;
  hdel?: (key: string, field: string) => Promise<unknown>;
  del?: (key: string) => Promise<unknown>;
  expire?: (key: string, seconds: number) => Promise<unknown>;
};

const MAX_IDENTIFIER_LENGTH = 256;
const MAX_DEVICE_LENGTH = 512;
const MAX_IP_LENGTH = 128;
const MAX_TOKEN_LENGTH = 16 * 1024;
const MAX_SESSION_TTL_SECONDS = 31 * 24 * 60 * 60;
const TOKEN_HASH_PATTERN = /^[A-Za-z0-9_-]{43}$/;

const assertIdentifier = (value: string, label: string): string => {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > MAX_IDENTIFIER_LENGTH ||
    containsControlCharacter(value)
  ) {
    throw new Error(`${label} must contain between 1 and 256 safe characters`);
  }
  return value;
};

const isStoredSession = (value: unknown): value is StoredSession => {
  if (!value || typeof value !== "object") return false;
  const session = value as Partial<StoredSession>;
  return (
    typeof session.sessionId === "string" &&
    session.sessionId.length > 0 &&
    session.sessionId.length <= MAX_IDENTIFIER_LENGTH &&
    !containsControlCharacter(session.sessionId) &&
    typeof session.device === "string" &&
    session.device.length <= MAX_DEVICE_LENGTH &&
    !containsControlCharacter(session.device) &&
    typeof session.ip === "string" &&
    session.ip.length <= MAX_IP_LENGTH &&
    !containsControlCharacter(session.ip) &&
    typeof session.createdAt === "number" &&
    Number.isSafeInteger(session.createdAt) &&
    session.createdAt > 0 &&
    ((typeof session.tokenHash === "string" &&
      TOKEN_HASH_PATTERN.test(session.tokenHash)) ||
      (typeof session.token === "string" &&
        session.token.length > 0 &&
        session.token.length <= MAX_TOKEN_LENGTH))
  );
};

const parseSession = (value: string | null | undefined): StoredSession | null => {
  if (!value || value.length > MAX_TOKEN_LENGTH + 2048) return null;
  try {
    const parsed: unknown = JSON.parse(value);
    return isStoredSession(parsed) ? parsed : null;
  } catch {
    return null;
  }
};

const metadataFromSession = (session: StoredSession): SessionMetadata => ({
  sessionId: session.sessionId,
  device: session.device,
  ip: session.ip,
  createdAt: session.createdAt,
});

const validateMetadata = (metadata: SessionMetadata): void => {
  assertIdentifier(metadata.sessionId, "sessionId");
  if (
    typeof metadata.device !== "string" ||
    metadata.device.length > MAX_DEVICE_LENGTH ||
    containsControlCharacter(metadata.device)
  ) {
    throw new Error(`session device must not exceed ${MAX_DEVICE_LENGTH} characters`);
  }
  if (
    typeof metadata.ip !== "string" ||
    metadata.ip.length > MAX_IP_LENGTH ||
    containsControlCharacter(metadata.ip)
  ) {
    throw new Error(`session IP must not exceed ${MAX_IP_LENGTH} characters`);
  }
  if (
    !Number.isSafeInteger(metadata.createdAt) ||
    metadata.createdAt <= 0
  ) {
    throw new Error("session createdAt must be a positive timestamp");
  }
};

export class SessionStore {
  private readonly namespace: string;

  constructor(
    private readonly redis?: SessionRedisClient,
    namespace = "sessions",
  ) {
    this.namespace = validateRedisKeyPrefix(namespace);
  }

  private sessionKey(principalId: string): string {
    return `${this.namespace}:${assertIdentifier(principalId, "principalId")}`;
  }

  private sessionField(sessionId: string): string {
    return assertIdentifier(sessionId, "sessionId");
  }

  async list(principalId: string): Promise<SessionMetadata[]> {
    if (!this.redis?.hgetall) return [];
    const sessions = await this.redis.hgetall(this.sessionKey(principalId));
    return Object.entries(sessions || {})
      .map(([field, value]) => {
        const session = parseSession(value);
        return session?.sessionId === field ? session : null;
      })
      .filter((session): session is StoredSession => !!session)
      .map(metadataFromSession);
  }

  async get(principalId: string, sessionId: string): Promise<StoredSession | null> {
    if (!this.redis) return null;
    const key = this.sessionKey(principalId);
    const field = this.sessionField(sessionId);
    if (this.redis.hget) {
      const session = parseSession(await this.redis.hget(key, field));
      return session?.sessionId === field ? session : null;
    }
    if (!this.redis.hgetall) return null;
    const sessions = await this.redis.hgetall(key);
    const session = parseSession(sessions?.[field]);
    return session?.sessionId === field ? session : null;
  }

  async upsert(
    principalId: string,
    token: string,
    metadata: SessionMetadata,
    ttlSeconds: number,
  ): Promise<void> {
    if (!this.redis?.hset) return;
    if (
      typeof token !== "string" ||
      token.length === 0 ||
      token.length > MAX_TOKEN_LENGTH
    ) {
      throw new Error("session token is invalid or too large");
    }
    validateMetadata(metadata);
    if (
      !Number.isSafeInteger(ttlSeconds) ||
      ttlSeconds < 1 ||
      ttlSeconds > MAX_SESSION_TTL_SECONDS
    ) {
      throw new Error("session TTL must be between 1 second and 31 days");
    }

    const key = this.sessionKey(principalId);
    await this.redis.hset(
      key,
      this.sessionField(metadata.sessionId),
      JSON.stringify({ tokenHash: tokenFingerprint(token), ...metadata }),
    );
    if (this.redis.expire) {
      await this.redis.expire(key, ttlSeconds);
    }
  }

  async updateToken(
    principalId: string,
    sessionId: string,
    token: string,
    ttlSeconds: number,
    defaults?: Partial<Omit<SessionMetadata, "sessionId">>,
  ): Promise<void> {
    const existing = await this.get(principalId, sessionId);
    const metadata: SessionMetadata = existing
      ? metadataFromSession(existing)
      : {
          sessionId,
          device: defaults?.device ?? "unknown",
          ip: defaults?.ip ?? "unknown",
          createdAt: defaults?.createdAt ?? Date.now(),
        };
    await this.upsert(principalId, token, metadata, ttlSeconds);
  }

  async tokenMatches(
    principalId: string,
    sessionId: string,
    token: string,
  ): Promise<boolean> {
    const session = await this.get(principalId, sessionId);
    return session ? sessionTokenMatches(session, token) : false;
  }

  async revoke(principalId: string, sessionId: string): Promise<void> {
    if (!this.redis?.hdel) return;
    await this.redis.hdel(
      this.sessionKey(principalId),
      this.sessionField(sessionId),
    );
  }

  async revokeAll(principalId: string): Promise<void> {
    if (!this.redis?.del) return;
    await this.redis.del(this.sessionKey(principalId));
  }
}

export const sessionTokenMatches = (
  session: StoredSession,
  token: string,
): boolean => {
  if (session.tokenHash) {
    return tokenFingerprintMatches(session.tokenHash, token);
  }
  return session.token
    ? tokenFingerprintMatches(tokenFingerprint(session.token), token)
    : false;
};
