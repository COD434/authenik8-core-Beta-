import { describe, expect, it, vi } from "vitest";
import { RedisSessionRiskStore } from "../../risk/redisSessionRiskStore";

describe("RedisSessionRiskStore", () => {
  it("uses bounded TTL writes and atomic NX deduplication", async () => {
    const redis = {
      get: vi.fn(),
      set: vi.fn().mockResolvedValue("OK"),
      incr: vi.fn(),
      expire: vi.fn(),
      del: vi.fn(),
    };
    const store = new RedisSessionRiskStore(redis as any);

    await store.set("risk:key", "value", 60);
    await expect(
      store.setIfAbsent("risk:seen", "1", 300),
    ).resolves.toBe(true);

    expect(redis.set).toHaveBeenNthCalledWith(
      1,
      "risk:key",
      "value",
      "EX",
      60,
    );
    expect(redis.set).toHaveBeenNthCalledWith(
      2,
      "risk:seen",
      "1",
      "EX",
      300,
      "NX",
    );
  });

  it("does not issue an invalid zero-key Redis delete", async () => {
    const redis = { del: vi.fn() };
    const store = new RedisSessionRiskStore(redis as any);

    await store.delete([]);

    expect(redis.del).not.toHaveBeenCalled();
  });
});
