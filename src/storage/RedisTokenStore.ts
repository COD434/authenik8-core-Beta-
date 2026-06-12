
import { Redis } from "ioredis";

export class RedisTokenStore {
	private prefix = "auth:v1";

  constructor(private redis?: any, _debug = false) {}


  private key(...parts:string[]){
  return `${this.prefix}:${parts.join(":")}`;
  }

 async storeRefreshToken(token:string,userId:string,ttl:number){
 const key = this.key("refresh", userId);
 await this.redis.set(key,userId, "EX",ttl);

}

async getRefreshToken(userId:string){
const key = this.key("refresh",userId);
const value = await this.redis.get(key);
return value;
}
async getset(key: string, value: string, expiry?: number): Promise<string | null> {

  const previous = await this.redis.getset(key, value);

  if (expiry) {
    await this.redis.expire(key, expiry);
  }

  return previous;
}

async deleteRefreshToken(userId:string){
const key = this.key("refresh",userId);
await this.redis.del(key);

}

async blacklistToken(userId: string, ttl: number) {
    const key = this.key("blacklist", userId);
    await this.redis.set(key, "1", "EX", ttl);
  }

  async isBlacklisted(userId: string) {
    const key = this.key("blacklist", userId);
    const exists = await this.redis.exists(key);
    return exists === 1;
  }

  // Rate Limiting
  async incrementRateLimit(ip: string, ttl: number) {
    const key = this.key("rate", ip);

    const count = await this.redis.incr(key);
    if (count === 1) {
      await this.redis.expire(key, ttl);
    }

    return count;
  }

  // IP Whitelist
  async addToWhitelist(ip: string) {
    const key = this.key("whitelist", ip);
    await this.redis.set(key, "1");
  }

  async removeFromWhitelist(ip: string) {
    const key = this.key("whitelist", ip);
    await this.redis.del(key);
  }

  async isWhitelisted(ip: string) {
    const key = this.key("whitelist", ip);
    const exists = await this.redis.exists(key);
    return exists === 1;
  }
async set(key: string, value: string, expiry?: number): Promise<void> {
  if (expiry) {
    await this.redis.set(key, value, "EX", expiry);
  } else {
    await this.redis.set(key, value);
  }
}


  async get(key: string): Promise<string | null> {
  return this.redis.get(key);
  }
}
