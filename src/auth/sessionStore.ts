export interface SessionMetadata {
  sessionId: string;
  device: string;
  ip: string;
  createdAt: number;
}

export type StoredSession = SessionMetadata & {
  token: string;
};

export type SessionRedisClient = {
  hget?: (key: string, field: string) => Promise<string | null>;
  hgetall?: (key: string) => Promise<Record<string, string> | null>;
  hset?: (key: string, field: string, value: string) => Promise<unknown>;
  hdel?: (key: string, field: string) => Promise<unknown>;
  del?: (key: string) => Promise<unknown>;
  expire?: (key: string, seconds: number) => Promise<unknown>;
};

const sessionKey = (userId: string) => `sessions:${userId}`;

const parseSession = (value: string | null | undefined): StoredSession | null => {
  if (!value) return null;

  try {
    const parsed = JSON.parse(value) as StoredSession;
    if (!parsed.sessionId || !parsed.token) return null;
    return parsed;
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

export class SessionStore {
  constructor(private readonly redis?: SessionRedisClient) {}

  async list(userId: string): Promise<SessionMetadata[]> {
    if (!this.redis?.hgetall) return [];

    const sessions = await this.redis.hgetall(sessionKey(userId));
    return Object.values(sessions || {})
      .map(parseSession)
      .filter((session): session is StoredSession => !!session)
      .map(metadataFromSession);
  }

  async get(userId: string, sessionId: string): Promise<StoredSession | null> {
    if (!this.redis) return null;

    if (this.redis.hget) {
      return parseSession(await this.redis.hget(sessionKey(userId), sessionId));
    }

    if (!this.redis.hgetall) return null;

    const sessions = await this.redis.hgetall(sessionKey(userId));
    return parseSession(sessions?.[sessionId]);
  }

  async upsert(
    userId: string,
    token: string,
    metadata: SessionMetadata,
    ttlSeconds: number
  ): Promise<void> {
    if (!this.redis?.hset) return;

    await this.redis.hset(
      sessionKey(userId),
      metadata.sessionId,
      JSON.stringify({ token, ...metadata })
    );

    if (this.redis.expire) {
      await this.redis.expire(sessionKey(userId), ttlSeconds);
    }
  }

  async updateToken(
    userId: string,
    sessionId: string,
    token: string,
    ttlSeconds: number,
    defaults?: Partial<Omit<SessionMetadata, "sessionId">>
  ): Promise<void> {
    const existing = await this.get(userId, sessionId);
    const metadata: SessionMetadata = existing
      ? metadataFromSession(existing)
      : {
          sessionId,
          device: defaults?.device ?? "unknown",
          ip: defaults?.ip ?? "unknown",
          createdAt: defaults?.createdAt ?? Date.now(),
        };

    await this.upsert(userId, token, metadata, ttlSeconds);
  }

  async tokenMatches(
    userId: string,
    sessionId: string,
    token: string
  ): Promise<boolean> {
    const session = await this.get(userId, sessionId);
    return session?.token === token;
  }

  async revoke(userId: string, sessionId: string): Promise<void> {
    if (!this.redis?.hdel) return;
    await this.redis.hdel(sessionKey(userId), sessionId);
  }

  async revokeAll(userId: string): Promise<void> {
    if (!this.redis?.del) return;
    await this.redis.del(sessionKey(userId));
  }
}
