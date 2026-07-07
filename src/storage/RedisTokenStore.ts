const COMPARE_AND_SET_SCRIPT = `
if redis.call("GET", KEYS[1]) == ARGV[1] then
  if ARGV[3] ~= "" then
    redis.call("SET", KEYS[1], ARGV[2], "EX", tonumber(ARGV[3]))
  else
    redis.call("SET", KEYS[1], ARGV[2])
  end
  return 1
end
return 0
`;

export class RedisTokenStore {
  private readonly prefix = "auth:v1";

  constructor(private redis?: any, _debug = false) {}

  async storeRefreshToken(
    token: string,
    userId: string,
    ttl: number
  ): Promise<void> {
    await this.redis.set(this.key("refresh", userId), token, "EX", ttl);
  }

  async getRefreshToken(userId: string): Promise<string | null> {
    return this.redis.get(this.key("refresh", userId));
  }

  async compareAndSet(
    key: string,
    expected: string,
    value: string,
    expiry?: number
  ): Promise<boolean> {
    const result = await this.redis.eval(
      COMPARE_AND_SET_SCRIPT,
      1,
      key,
      expected,
      value,
      expiry ? expiry.toString() : ""
    );

    return Number(result) === 1;
  }

  async deleteRefreshToken(userId: string): Promise<void> {
    await this.redis.del(this.key("refresh", userId));
  }

  async del(key: string): Promise<void> {
    await this.redis.del(key);
  }

  async blacklistToken(userId: string, ttl: number): Promise<void> {
    await this.redis.set(this.key("blacklist", userId), "1", "EX", ttl);
  }

  async isBlacklisted(userId: string): Promise<boolean> {
    const exists = await this.redis.exists(this.key("blacklist", userId));
    return exists === 1;
  }

  async incrementRateLimit(ip: string, ttl: number): Promise<number> {
    const key = this.key("rate", ip);
    const count = await this.redis.incr(key);

    if (count === 1) {
      await this.redis.expire(key, ttl);
    }

    return count;
  }

  async addToWhitelist(ip: string): Promise<void> {
    await this.redis.set(this.key("whitelist", ip), "1");
  }

  async removeFromWhitelist(ip: string): Promise<void> {
    await this.redis.del(this.key("whitelist", ip));
  }

  async isWhitelisted(ip: string): Promise<boolean> {
    const exists = await this.redis.exists(this.key("whitelist", ip));
    return exists === 1;
  }

  async set(key: string, value: string, expiry?: number): Promise<void> {
    if (expiry) {
      await this.redis.set(key, value, "EX", expiry);
      return;
    }

    await this.redis.set(key, value);
  }

  async get(key: string): Promise<string | null> {
    return this.redis.get(key);
  }

  private key(...parts: string[]): string {
    return `${this.prefix}:${parts.join(":")}`;
  }
}
