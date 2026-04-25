import { SecurityModule } from "../security/ipService";

type FakeRedis = {
  sets: Map<string, Set<string>>;
  ttlKeys: Set<string>;
  sismember: (key: string, value: string) => Promise<number>;
  smembers: (key: string) => Promise<string[]>;
  sadd: (key: string, value: string) => Promise<void>;
  srem: (key: string, value: string) => Promise<void>;
  set: (key: string, value: string, mode: string, ttl: number) => Promise<void>;
  del: (key: string) => Promise<void>;
  exists: (key: string) => Promise<number>;
  on: () => void;
};

const createFakeRedis = (): FakeRedis => {
  const sets = new Map<string, Set<string>>();
  const ttlKeys = new Set<string>();

  return {
    sets,
    ttlKeys,
    async sismember(key, value) {
      return sets.get(key)?.has(value) ? 1 : 0;
    },
    async smembers(key) {
      return [...(sets.get(key) ?? new Set<string>())];
    },
    async sadd(key, value) {
      if (!sets.has(key)) {
        sets.set(key, new Set());
      }
      sets.get(key)?.add(value);
    },
    async srem(key, value) {
      sets.get(key)?.delete(value);
    },
    async set(key) {
      ttlKeys.add(key);
    },
    async del(key) {
      ttlKeys.delete(key);
    },
    async exists(key) {
      return ttlKeys.has(key) ? 1 : 0;
    },
    on() {},
  };
};

describe("SecurityModule whitelist middleware", () => {
  test("does not trust x-forwarded-for by default", async () => {
    const redis = createFakeRedis();
    const security = new SecurityModule({
      redisClient: redis as any,
      rateLimiterEnabled: false,
      whiteListEnabled: true,
    });

    await security.addIP("203.0.113.10");

    const req = {
      headers: {
        "x-forwarded-for": "203.0.113.10",
      },
      ip: "198.51.100.25",
      socket: {
        remoteAddress: "198.51.100.25",
      },
    } as any;
    const res = {
      statusCode: 200,
      body: null as any,
      status(code: number) {
        this.statusCode = code;
        return this;
      },
      json(payload: unknown) {
        this.body = payload;
        return this;
      },
    };
    let nextCalled = false;

    await security.whiteListMiddleware()(req, res as any, () => {
      nextCalled = true;
    });

    expect(nextCalled).toBe(false);
    expect(res.statusCode).toBe(403);
  });

  test("can trust x-forwarded-for when explicitly enabled", async () => {
    const redis = createFakeRedis();
    const security = new SecurityModule({
      redisClient: redis as any,
      rateLimiterEnabled: false,
      whiteListEnabled: true,
      trustProxyHeaders: true,
    });

    await security.addIP("203.0.113.10");

    const req = {
      headers: {
        "x-forwarded-for": "203.0.113.10",
      },
      ip: "198.51.100.25",
      socket: {
        remoteAddress: "198.51.100.25",
      },
    } as any;
    const res = {
      status() {
        return this;
      },
      json() {
        return this;
      },
    };
    let nextCalled = false;

    await security.whiteListMiddleware()(req, res as any, () => {
      nextCalled = true;
    });

    expect(nextCalled).toBe(true);
  });
});
