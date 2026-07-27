import type { Redis } from "ioredis";
import type { SessionRiskStore } from "./types";

export class RedisSessionRiskStore implements SessionRiskStore {
  constructor(private readonly redis: Redis) {}

  get(key: string): Promise<string | null> {
    return this.redis.get(key);
  }

  async set(key: string, value: string, ttlSeconds: number): Promise<void> {
    await this.redis.set(key, value, "EX", ttlSeconds);
  }

  async setIfAbsent(
    key: string,
    value: string,
    ttlSeconds: number,
  ): Promise<boolean> {
    return (
      (await this.redis.set(key, value, "EX", ttlSeconds, "NX")) === "OK"
    );
  }

  increment(key: string): Promise<number> {
    return this.redis.incr(key);
  }

  async expire(key: string, ttlSeconds: number): Promise<void> {
    await this.redis.expire(key, ttlSeconds);
  }

  async delete(keys: readonly string[]): Promise<void> {
    if (keys.length) await this.redis.del(...keys);
  }
}
