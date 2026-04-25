import { randomUUID } from "crypto";
import Redis from "ioredis";

const parseRedisUrlDb = (value?: string): number | undefined => {
  if (!value) {
    return undefined;
  }

  try {
    const pathname = new URL(value).pathname.replace(/^\//, "");
    if (!pathname) {
      return undefined;
    }

    const parsed = Number(pathname);
    return Number.isInteger(parsed) ? parsed : undefined;
  } catch {
    return undefined;
  }
};

const buildRedisClient = () => {
  const redisUrl = process.env.REDIS_URL;

  if (redisUrl) {
    return new Redis(redisUrl, {
      lazyConnect: true,
      enableReadyCheck: true,
      maxRetriesPerRequest: 1
    });
  }

  return new Redis({
    host: process.env.REDIS_HOST ?? "127.0.0.1",
    port: Number(process.env.REDIS_PORT ?? "6379"),
    db: parseRedisUrlDb(process.env.REDIS_URL),
    lazyConnect: true,
    enableReadyCheck: true,
    maxRetriesPerRequest: 1
  });
};

const scanKeys = async (redis: Redis, pattern: string): Promise<string[]> => {
  let cursor = "0";
  const keys: string[] = [];

  do {
    const [nextCursor, batch] = await redis.scan(cursor, "MATCH", pattern, "COUNT", 100);
    cursor = nextCursor;
    keys.push(...batch);
  } while (cursor !== "0");

  return keys;
};

export interface RedisTestHelper {
  redis: Redis;
  namespace: string;
  createUserId: (name: string) => string;
  cleanup: () => Promise<void>;
  close: () => Promise<void>;
}

export const createRedisTestHelper = async (suite: string): Promise<RedisTestHelper> => {
  const namespaceRoot = process.env.AUTHENIK8_TEST_NAMESPACE ?? "local";
  const namespace = `${namespaceRoot}:${suite}:${randomUUID()}`;
  const redis = buildRedisClient();

  await redis.connect();
  await redis.ping();

  const createUserId = (name: string) => `${namespace}:${name}`;

  const cleanup = async () => {
    const patterns = [
      `refresh:${namespace}:*`,
      `lock:${namespace}:*`,
      "oauth:v1:*"
    ];

    for (const pattern of patterns) {
      const keys = await scanKeys(redis, pattern);

      if (keys.length > 0) {
        await redis.del(...keys);
      }
    }
  };

  const close = async () => {
    await cleanup();
    await redis.quit();
  };

  return {
    redis,
    namespace,
    createUserId,
    cleanup,
    close
  };
};
