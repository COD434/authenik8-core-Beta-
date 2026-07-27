import { createHash } from "crypto";
import RedisMock from "ioredis-mock";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createRedisIdentityAdapter } from "../../oauth/adapters/redisAdapter";

const digest = (value: string): string =>
  createHash("sha256").update(value).digest("base64url");

describe("createRedisIdentityAdapter", () => {
  let redis: InstanceType<typeof RedisMock>;

  beforeEach(() => {
    redis = new RedisMock();
  });
  afterEach(async () => {
    await redis.flushall();
    redis.disconnect();
  });

  it("atomically creates and resolves every identity index", async () => {
    const adapter = createRedisIdentityAdapter(redis as never, "test:oauth:v1");
    const created = await adapter.createUser({
      email: " Person@Example.COM ",
      provider: "google",
      providerId: "google:123",
    });

    expect(created.status).toBe("created");
    expect(created.user.email).toBe("person@example.com");
    await expect(adapter.findUserById(created.user.id)).resolves.toEqual(
      created.user,
    );
    await expect(
      adapter.findUserByEmail("PERSON@example.com"),
    ).resolves.toEqual(created.user);
    await expect(
      adapter.findUserByProvider("google", "google:123"),
    ).resolves.toEqual(created.user);
  });

  it("classifies a concurrent same-email race and creates one account", async () => {
    const adapterA = createRedisIdentityAdapter(redis as never, "test:oauth:v1");
    const adapterB = createRedisIdentityAdapter(redis as never, "test:oauth:v1");

    const results = await Promise.all([
      adapterA.createUser({
        email: "victim@example.com",
        provider: "google",
        providerId: "google-1",
      }),
      adapterB.createUser({
        email: "victim@example.com",
        provider: "github",
        providerId: "github-1",
      }),
    ]);

    expect(results.map((result) => result.status).sort()).toEqual([
      "created",
      "existing-email",
    ]);
    expect(results[0].user.id).toBe(results[1].user.id);
    expect((await redis.keys("test:oauth:v1:{identity}:user:*"))).toHaveLength(1);
  });

  it("classifies a concurrent exact-provider race as safe provider ownership", async () => {
    const adapter = createRedisIdentityAdapter(redis as never, "test:oauth:v1");
    const [first, second] = await Promise.all([
      adapter.createUser({
        email: "one@example.com",
        provider: "google",
        providerId: "same-provider",
      }),
      adapter.createUser({
        email: "two@example.com",
        provider: "google",
        providerId: "same-provider",
      }),
    ]);

    expect([first.status, second.status].sort()).toEqual([
      "created",
      "existing-provider",
    ]);
    expect(first.user.id).toBe(second.user.id);
  });

  it("preserves concurrent provider links without lost updates", async () => {
    const adapter = createRedisIdentityAdapter(redis as never, "test:oauth:v1");
    const user = (
      await adapter.createUser({
        email: "one@example.com",
        provider: "google",
        providerId: "google-1",
      })
    ).user;

    await Promise.all([
      adapter.linkProvider(user.id, "github", "github-1"),
      adapter.linkProvider(user.id, "github", "github-2"),
    ]);

    const linked = await adapter.findUserById(user.id);
    expect(linked?.providers).toEqual(
      expect.arrayContaining([
        { provider: "google", providerId: "google-1" },
        { provider: "github", providerId: "github-1" },
        { provider: "github", providerId: "github-2" },
      ]),
    );
  });

  it("rejects linking a provider to a second account", async () => {
    const adapter = createRedisIdentityAdapter(redis as never, "test:oauth:v1");
    const first = (
      await adapter.createUser({
        email: "one@example.com",
        provider: "google",
        providerId: "google-1",
      })
    ).user;
    const second = (
      await adapter.createUser({
        email: "two@example.com",
        provider: "github",
        providerId: "github-2",
      })
    ).user;

    await expect(
      adapter.linkProvider(second.id, "google", "google-1"),
    ).rejects.toThrow(/already linked/i);
    expect(
      (await adapter.findUserById(first.id))?.providers,
    ).toHaveLength(1);
  });

  it("rejects malformed identity records from the security-critical store", async () => {
    const adapter = createRedisIdentityAdapter(redis as never, "test:oauth:v1");
    const user = (
      await adapter.createUser({
        email: "one@example.com",
        provider: "google",
        providerId: "google-1",
      })
    ).user;
    const [userKey] = await redis.keys("test:oauth:v1:{identity}:user:*");
    await redis.set(
      userKey!,
      JSON.stringify({ ...user, id: "forged\nidentity" }),
    );

    await expect(adapter.findUserById(user.id)).rejects.toThrow(
      /invalid user record/i,
    );
  });

  it("bounds provider links per stored identity", async () => {
    const adapter = createRedisIdentityAdapter(redis as never, "test:oauth:v1");
    const user = (
      await adapter.createUser({
        email: "one@example.com",
        provider: "google",
        providerId: "google-1",
      })
    ).user;
    for (let index = 1; index < 32; index += 1) {
      await adapter.linkProvider(user.id, "github", `github-${index}`);
    }

    await expect(
      adapter.linkProvider(user.id, "github", "github-overflow"),
    ).rejects.toThrow(/provider limit/i);
  });

  it("cross-checks email and provider indexes against the resolved user", async () => {
    const prefix = "test:oauth:v1";
    const adapter = createRedisIdentityAdapter(redis as never, prefix);
    const first = (
      await adapter.createUser({
        email: "one@example.com",
        provider: "google",
        providerId: "google-1",
      })
    ).user;
    const second = (
      await adapter.createUser({
        email: "two@example.com",
        provider: "github",
        providerId: "github-2",
      })
    ).user;

    await redis.set(
      `${prefix}:{identity}:email:${digest(first.email)}`,
      second.id,
    );
    await expect(adapter.findUserByEmail(first.email)).rejects.toThrow(
      /email index integrity/i,
    );

    await redis.set(
      `${prefix}:{identity}:provider:${digest("google\0google-1")}`,
      second.id,
    );
    await expect(
      adapter.findUserByProvider("google", "google-1"),
    ).rejects.toThrow(/provider index integrity/i);
  });
});
