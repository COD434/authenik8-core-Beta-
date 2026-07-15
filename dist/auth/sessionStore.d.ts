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
export declare class SessionStore {
    private readonly redis?;
    private readonly namespace;
    constructor(redis?: SessionRedisClient | undefined, namespace?: string);
    private sessionKey;
    list(principalId: string): Promise<SessionMetadata[]>;
    get(principalId: string, sessionId: string): Promise<StoredSession | null>;
    upsert(principalId: string, token: string, metadata: SessionMetadata, ttlSeconds: number): Promise<void>;
    updateToken(principalId: string, sessionId: string, token: string, ttlSeconds: number, defaults?: Partial<Omit<SessionMetadata, "sessionId">>): Promise<void>;
    tokenMatches(principalId: string, sessionId: string, token: string): Promise<boolean>;
    revoke(principalId: string, sessionId: string): Promise<void>;
    revokeAll(principalId: string): Promise<void>;
}
//# sourceMappingURL=sessionStore.d.ts.map