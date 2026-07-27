import { describe, expect, it, vi } from "vitest";
import { SessionRiskService } from "../../risk/sessionRiskService";
import type { SessionRiskStore } from "../../risk/types";

class MemoryRiskStore implements SessionRiskStore {
  readonly values = new Map<string, string>();
  readonly counters = new Map<string, number>();

  async get(key: string) {
    return this.values.get(key) ?? null;
  }

  async set(key: string, value: string) {
    this.values.set(key, value);
  }

  async setIfAbsent(key: string, value: string) {
    if (this.values.has(key)) return false;
    this.values.set(key, value);
    return true;
  }

  async increment(key: string) {
    const count = (this.counters.get(key) ?? 0) + 1;
    this.counters.set(key, count);
    return count;
  }

  async expire() {}

  async delete(keys: readonly string[]) {
    keys.forEach((key) => {
      this.values.delete(key);
      this.counters.delete(key);
    });
  }
}

const human = {
  kind: "human" as const,
  id: "user-1",
  sessionId: "session-1",
};

describe("SessionRiskService", () => {
  it("quarantines a replayed refresh family immediately", async () => {
    const audit = { emit: vi.fn().mockResolvedValue(undefined) };
    const risk = new SessionRiskService(new MemoryRiskStore(), {}, audit);

    const state = await risk.report({
      type: "refresh_replay",
      principal: human,
    });

    expect(state).toMatchObject({
      status: "quarantined",
      reasons: ["refresh_replay"],
      quarantinedAt: expect.any(String),
      expiresAt: expect.any(String),
    });
    await expect(risk.isQuarantined(human)).resolves.toBe(true);
    expect(audit.emit).toHaveBeenCalledWith(
      expect.objectContaining({ type: "session.quarantined" }),
    );
  });

  it("quarantines repeated concurrent refresh attempts at the configured threshold", async () => {
    const risk = new SessionRiskService(new MemoryRiskStore(), {
      concurrentRefreshThreshold: 2,
    });

    await expect(
      risk.report({ type: "concurrent_refresh", principal: human }),
    ).resolves.toMatchObject({ status: "active" });
    await expect(
      risk.report({ type: "concurrent_refresh", principal: human }),
    ).resolves.toMatchObject({
      status: "quarantined",
      reasons: ["concurrent_refresh"],
    });
  });

  it("audits context changes by default without false-positive quarantine", async () => {
    const risk = new SessionRiskService(new MemoryRiskStore());

    await expect(
      risk.assessContext(
        human,
        { ip: "203.0.113.1", device: "browser-a" },
        { ip: "203.0.113.2", device: "browser-b" },
      ),
    ).resolves.toMatchObject({ status: "active" });
  });

  it("supports policy-driven quarantine and deduplicates identical context changes", async () => {
    const store = new MemoryRiskStore();
    const risk = new SessionRiskService(store, {
      ipChangeAction: "quarantine",
    });

    const first = await risk.assessContext(
      human,
      { ip: "203.0.113.1" },
      { ip: "203.0.113.2" },
    );
    const counterCount = store.counters.size;
    await risk.assessContext(
      human,
      { ip: "203.0.113.1" },
      { ip: "203.0.113.2" },
    );

    expect(first.status).toBe("quarantined");
    expect(store.counters.size).toBe(counterCount);
  });

  it("releases quarantine and resets bounded signal counters", async () => {
    const risk = new SessionRiskService(new MemoryRiskStore());
    await risk.report({ type: "refresh_replay", principal: human });

    await risk.release(human);

    await expect(risk.getState(human)).resolves.toEqual({
      status: "active",
      reasons: [],
    });
  });

  it("fails closed on malformed stored quarantine state", async () => {
    const store = new MemoryRiskStore();
    const risk = new SessionRiskService(store);
    await risk.quarantine(human, ["refresh_replay"]);
    const quarantineKey = [...store.values.keys()].find((key) =>
      key.endsWith(":quarantine"),
    )!;
    store.values.set(
      quarantineKey,
      JSON.stringify({
        status: "quarantined",
        reasons: ["invented-signal"],
        quarantinedAt: "not-a-date",
        expiresAt: "not-a-date",
      }),
    );

    await expect(risk.isQuarantined(human)).rejects.toThrow(
      /stored risk state/i,
    );
  });

  it("hashes deduplication fingerprints before constructing Redis keys", async () => {
    const store = new MemoryRiskStore();
    const risk = new SessionRiskService(store);

    await risk.report({
      type: "concurrent_refresh",
      principal: human,
      fingerprint: "caller:controlled:value",
    });

    expect(
      [...store.values.keys()].some((key) =>
        key.includes("caller:controlled:value"),
      ),
    ).toBe(false);
  });

  it("rejects invalid runtime policy and principal values", async () => {
    expect(
      () =>
        new SessionRiskService(new MemoryRiskStore(), {
          ipChangeAction: "permit" as never,
        }),
    ).toThrow(/context actions/i);
    expect(
      () =>
        new SessionRiskService(new MemoryRiskStore(), {
          enabled: 0 as never,
        }),
    ).toThrow(/enabled.*boolean/i);

    const risk = new SessionRiskService(new MemoryRiskStore());
    await expect(
      risk.report({
        type: "refresh_replay",
        principal: { ...human, id: "user\nforged" },
      }),
    ).rejects.toThrow(/principal/i);
  });
});
