import { describe, expect, it, vi } from "vitest";
import { SessionStore } from "../../auth/sessionStore";
import { tokenFingerprint } from "../../auth/tokenFingerprint";

const storedSession = (sessionId: string) =>
  JSON.stringify({
    sessionId,
    device: "browser",
    ip: "192.0.2.1",
    createdAt: Date.now(),
    tokenHash: tokenFingerprint("header.payload.signature"),
  });

describe("SessionStore integrity checks", () => {
  it("rejects a record whose embedded session ID differs from its hash field", async () => {
    const redis = {
      hget: vi.fn().mockResolvedValue(storedSession("forged-session")),
      hgetall: vi.fn().mockResolvedValue({
        "expected-session": storedSession("forged-session"),
      }),
    };
    const store = new SessionStore(redis, "test:sessions");

    await expect(
      store.get("user-1", "expected-session"),
    ).resolves.toBeNull();
    await expect(store.list("user-1")).resolves.toEqual([]);
  });

  it("rejects control characters in persisted session metadata", async () => {
    const redis = {
      hget: vi.fn().mockResolvedValue(
        JSON.stringify({
          sessionId: "session-1",
          device: "browser\nforged",
          ip: "192.0.2.1",
          createdAt: Date.now(),
          tokenHash: tokenFingerprint("header.payload.signature"),
        }),
      ),
    };
    const store = new SessionStore(redis, "test:sessions");

    await expect(store.get("user-1", "session-1")).resolves.toBeNull();
  });
});
