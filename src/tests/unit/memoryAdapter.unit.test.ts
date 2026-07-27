import { beforeEach, describe, expect, it } from "vitest";
import { memoryAdapter } from "../../oauth/adapters/memoryAdapter";

describe("memoryAdapter", () => {
  beforeEach(() => memoryAdapter.reset());

  it("creates, normalizes, and resolves a user through every index", async () => {
    const created = await memoryAdapter.createUser({
      email: " Test@Example.COM ",
      provider: "google",
      providerId: "google-123",
    });

    expect(created.status).toBe("created");
    expect(created.user.email).toBe("test@example.com");
    await expect(memoryAdapter.findUserById(created.user.id)).resolves.toEqual(
      created.user,
    );
    await expect(
      memoryAdapter.findUserByEmail("TEST@example.com"),
    ).resolves.toEqual(created.user);
    await expect(
      memoryAdapter.findUserByProvider("google", "google-123"),
    ).resolves.toEqual(created.user);
  });

  it("classifies provider and email collisions without creating duplicates", async () => {
    const first = await memoryAdapter.createUser({
      email: "one@example.com",
      provider: "google",
      providerId: "provider-1",
    });
    const providerCollision = await memoryAdapter.createUser({
      email: "other@example.com",
      provider: "google",
      providerId: "provider-1",
    });
    const emailCollision = await memoryAdapter.createUser({
      email: "ONE@example.com",
      provider: "github",
      providerId: "provider-2",
    });

    expect(first.status).toBe("created");
    expect(providerCollision.status).toBe("existing-provider");
    expect(emailCollision.status).toBe("existing-email");
    expect(memoryAdapter.dump()).toHaveLength(1);
  });

  it("links idempotently and rejects a provider owned by another user", async () => {
    const first = (
      await memoryAdapter.createUser({
        email: "one@example.com",
        provider: "google",
        providerId: "google-1",
      })
    ).user;
    const second = (
      await memoryAdapter.createUser({
        email: "two@example.com",
        provider: "github",
        providerId: "github-2",
      })
    ).user;

    await memoryAdapter.linkProvider(first.id, "github", "github-1");
    await memoryAdapter.linkProvider(first.id, "github", "github-1");
    expect((await memoryAdapter.findUserById(first.id))?.providers).toHaveLength(
      2,
    );
    await expect(
      memoryAdapter.linkProvider(second.id, "google", "google-1"),
    ).rejects.toThrow(/already linked/i);
  });

  it("returns detached values so callers cannot mutate stored identity state", async () => {
    const created = await memoryAdapter.createUser({
      email: "one@example.com",
      provider: "google",
      providerId: "google-1",
    });
    created.user.providers.push({ provider: "github", providerId: "injected" });

    expect((await memoryAdapter.findUserById(created.user.id))?.providers).toEqual(
      [{ provider: "google", providerId: "google-1" }],
    );
  });

  it("bounds the number of linked providers per identity", async () => {
    const created = await memoryAdapter.createUser({
      email: "one@example.com",
      provider: "google",
      providerId: "google-1",
    });
    for (let index = 1; index < 32; index += 1) {
      await memoryAdapter.linkProvider(
        created.user.id,
        "github",
        `github-${index}`,
      );
    }

    await expect(
      memoryAdapter.linkProvider(created.user.id, "github", "github-overflow"),
    ).rejects.toThrow(/provider limit/i);
  });
});
