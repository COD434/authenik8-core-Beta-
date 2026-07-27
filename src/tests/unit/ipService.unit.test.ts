import type { NextFunction, Request, Response } from "express";
import RedisMock from "ioredis-mock";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { SecurityModule } from "../../security/ipService";

const { consume } = vi.hoisted(() => ({ consume: vi.fn() }));
vi.mock("rate-limiter-flexible", () => ({
  RateLimiterRedis: vi.fn(function () {
    return { consume };
  }),
}));

const request = (
  remoteAddress: string,
  forwarded?: string,
): Request =>
  ({
    socket: { remoteAddress },
    headers: forwarded ? { "x-forwarded-for": forwarded } : {},
  }) as unknown as Request;

const response = () =>
  ({
    status: vi.fn().mockReturnThis(),
    json: vi.fn().mockReturnThis(),
    send: vi.fn().mockReturnThis(),
  }) as unknown as Response;

describe("SecurityModule", () => {
  let redis: InstanceType<typeof RedisMock>;
  let security: SecurityModule;

  beforeEach(() => {
    redis = new RedisMock();
    consume.mockReset();
    consume.mockResolvedValue(undefined);
    security = new SecurityModule({
      redisClient: redis as never,
      rateLimiterEnabled: false,
      keyPrefix: "test:security",
    });
  });
  afterEach(async () => {
    await redis.flushall();
    redis.disconnect();
  });

  it("enforces exact allowlist TTL atomically", async () => {
    await security.addIP("203.0.113.10", 60);
    await expect(security.isAllowed("203.0.113.10")).resolves.toBe(true);

    const marker = (await redis.keys("test:security:{allowlist}:entry:*"))[0]!;
    await redis.del(marker);
    await expect(security.isAllowed("203.0.113.10")).resolves.toBe(false);
    await expect(
      redis.smembers("test:security:{allowlist}:exact"),
    ).resolves.toEqual([]);
  });

  it("does not implicitly trust IPv4 or IPv6 loopback", async () => {
    await expect(security.isAllowed("127.0.0.1")).resolves.toBe(false);
    await expect(security.isAllowed("::1")).resolves.toBe(false);
    await security.addIP("::1");
    await expect(security.isAllowed("::1")).resolves.toBe(true);
  });

  it("canonicalizes and matches IPv4 and IPv6 CIDRs", async () => {
    await security.addIP("10.42.7.9/8");
    await security.addIP("2001:db8:1::9/64");

    await expect(security.isAllowed("10.99.1.2")).resolves.toBe(true);
    await expect(security.isAllowed("2001:db8:1::abcd")).resolves.toBe(true);
    await expect(security.isAllowed("2001:db8:2::1")).resolves.toBe(false);
    await expect(security.listIPs()).resolves.toEqual([
      "10.0.0.0/8",
      "2001:db8:1::/64",
    ]);
  });

  it("rejects malformed entries and unsafe TTLs", async () => {
    await expect(security.addIP("not-an-ip")).rejects.toThrow(/invalid/i);
    await expect(security.addIP("10.0.0.1", 0)).rejects.toThrow(/TTL/i);
    await expect(security.isAllowed("not-an-ip")).resolves.toBe(false);
  });

  it("ignores forwarded headers when no proxy network is trusted", async () => {
    await security.addIP("203.0.113.10");
    const res = response();
    const next: NextFunction = vi.fn();

    await security.whiteListMiddleware()(
      request("198.51.100.20", "203.0.113.10"),
      res,
      next,
    );
    expect(next).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(403);
  });

  it("walks a trusted proxy chain from the socket inward", async () => {
    security = new SecurityModule({
      redisClient: redis as never,
      rateLimiterEnabled: false,
      keyPrefix: "test:security",
      trustedProxyCidrs: ["10.0.0.0/8"],
    });
    await security.addIP("203.0.113.10");
    const next: NextFunction = vi.fn();

    await security.whiteListMiddleware()(
      request("10.0.0.2", "203.0.113.10, 10.0.0.1"),
      response(),
      next,
    );
    expect(next).toHaveBeenCalledOnce();
  });

  it("stops at the first untrusted proxy instead of accepting a spoofed leftmost hop", async () => {
    security = new SecurityModule({
      redisClient: redis as never,
      rateLimiterEnabled: false,
      keyPrefix: "test:security",
      trustedProxyCidrs: ["10.0.0.0/8"],
    });
    await security.addIP("203.0.113.10");
    const next: NextFunction = vi.fn();

    await security.whiteListMiddleware()(
      request("10.0.0.2", "203.0.113.10, 198.51.100.20"),
      response(),
      next,
    );
    expect(next).not.toHaveBeenCalled();
  });

  it("rejects blanket proxy trust without authenticated proxy networks", () => {
    expect(
      () =>
        new SecurityModule({
          redisClient: redis as never,
          trustProxyHeaders: true,
        }),
    ).toThrow(/trustedProxyCidrs/);
  });

  it("rejects coercible, conflicting, and unbounded security options", () => {
    expect(
      () =>
        new SecurityModule({
          redisClient: redis as never,
          whiteListEnabled: 0 as never,
        }),
    ).toThrow(/boolean/i);
    expect(
      () =>
        new SecurityModule({
          redisClient: redis as never,
          whiteListEnabled: true,
          enableWhitelist: false,
        }),
    ).toThrow(/conflicts/i);
    expect(
      () =>
        new SecurityModule({
          redisClient: redis as never,
          rateLimitPoints: 1_000_001,
        }),
    ).toThrow(/1000000/i);
  });

  it("fails closed when Redis is unavailable", async () => {
    vi.spyOn(redis, "eval").mockRejectedValueOnce(new Error("down"));
    await expect(security.isAllowed("203.0.113.10")).resolves.toBe(false);
  });

  it("applies the configured rate limit to the resolved client", async () => {
    const limited = new SecurityModule({
      redisClient: redis as never,
      whiteListEnabled: false,
      keyPrefix: "test:security",
    });
    consume.mockRejectedValueOnce({
      msBeforeNext: 1000,
      remainingPoints: 0,
      consumedPoints: 101,
    });
    const res = response();
    await limited.rateLimiterMiddleware()(
      request("192.0.2.20"),
      res,
      vi.fn(),
    );
    expect(consume).toHaveBeenCalledWith("192.0.2.20");
    expect(res.status).toHaveBeenCalledWith(429);
  });

  it("fails closed with 503 when the rate-limit store is unavailable", async () => {
    const limited = new SecurityModule({
      redisClient: redis as never,
      whiteListEnabled: false,
      keyPrefix: "test:security",
    });
    consume.mockRejectedValueOnce(new Error("Redis unavailable"));
    const res = response();
    await limited.rateLimiterMiddleware()(
      request("192.0.2.20"),
      res,
      vi.fn(),
    );
    expect(res.status).toHaveBeenCalledWith(503);
  });

  it("does not mistake an unknown thrown object for a rate-limit decision", async () => {
    const limited = new SecurityModule({
      redisClient: redis as never,
      whiteListEnabled: false,
      keyPrefix: "test:security",
    });
    consume.mockRejectedValueOnce({ unexpected: "store protocol failure" });
    const res = response();
    await limited.rateLimiterMiddleware()(
      request("192.0.2.20"),
      res,
      vi.fn(),
    );
    expect(res.status).toHaveBeenCalledWith(503);
  });

  it("provides enforcing Helmet defaults and a disabled pass-through", () => {
    expect(typeof security.helmetMiddleware()).toBe("function");
    const disabled = new SecurityModule({
      redisClient: redis as never,
      helmetEnabled: false,
      rateLimiterEnabled: false,
    });
    const next: NextFunction = vi.fn();
    disabled.helmetMiddleware()(request("192.0.2.1"), response(), next);
    expect(next).toHaveBeenCalledOnce();
  });
});
