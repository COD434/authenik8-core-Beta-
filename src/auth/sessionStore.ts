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
  constructor(
    private readonly redis?: SessionRedisClient,
    private readonly namespace = "sessions",
  ) {}

  private sessionKey(principalId: string): string {
    return `${this.namespace}:${principalId}`;
  }

  async list(principalId: string): Promise<SessionMetadata[]> {
    if (!this.redis?.hgetall) return [];

    const sessions = await this.redis.hgetall(this.sessionKey(principalId));
    return Object.values(sessions || {})
      .map(parseSession)
      .filter((session): session is StoredSession => !!session)
      .map(metadataFromSession);
  }

  async get(principalId: string, sessionId: string): Promise<StoredSession | null> {
    if (!this.redis) return null;

    if (this.redis.hget) {
      return parseSession(
        await this.redis.hget(this.sessionKey(principalId), sessionId),
      );
    }

    if (!this.redis.hgetall) return null;

    const sessions = await this.redis.hgetall(this.sessionKey(principalId));
    return parseSession(sessions?.[sessionId]);
  }

  async upsert(
    principalId: string,
    token: string,
    metadata: SessionMetadata,
    ttlSeconds: number
  ): Promise<void> {
    if (!this.redis?.hset) return;

    await this.redis.hset(
      this.sessionKey(principalId),
      metadata.sessionId,
      JSON.stringify({ token, ...metadata })
    );

    if (this.redis.expire) {
      await this.redis.expire(this.sessionKey(principalId), ttlSeconds);
    }
  }

  async updateToken(
    principalId: string,
    sessionId: string,
    token: string,
    ttlSeconds: number,
    defaults?: Partial<Omit<SessionMetadata, "sessionId">>
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
    token: string
  ): Promise<boolean> {
    const session = await this.get(principalId, sessionId);
    return session?.token === token;
  }

  async revoke(principalId: string, sessionId: string): Promise<void> {
    if (!this.redis?.hdel) return;
    await this.redis.hdel(this.sessionKey(principalId), sessionId);
  }

  async revokeAll(principalId: string): Promise<void> {
    if (!this.redis?.del) return;
    await this.redis.del(this.sessionKey(principalId));
  }
}
