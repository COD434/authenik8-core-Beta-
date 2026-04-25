import Redis from "ioredis";
import { createAuthenik8 } from "../createAuthenik8";
import { createRedisTestHelper, RedisTestHelper } from "./helpers/redisTestHelper";

describe("OAuth identity issuance", () => {
  let redisHelper: RedisTestHelper;
  let secondaryRedis: Redis;

  beforeAll(async () => {
    redisHelper = await createRedisTestHelper("oauth-identity");
    secondaryRedis = redisHelper.redis.duplicate();
    await secondaryRedis.connect();
  });

  afterAll(async () => {
    await secondaryRedis.quit();
    await redisHelper.close();
  });

  test("issues tokens against a stable internal user id across auth instances", async () => {
    const email = `${redisHelper.namespace}@example.com`;
    const providerId = `${redisHelper.namespace}:google`;
    const authA = await createAuthenik8({
      jwtSecret: "oauth-secret",
      refreshSecret: "oauth-refresh",
      redis: redisHelper.redis,
    });
    const authB = await createAuthenik8({
      jwtSecret: "oauth-secret",
      refreshSecret: "oauth-refresh",
      redis: secondaryRedis,
    });

    const firstTokens = await authA.issueTokensFromProfile({
      email,
      provider: "google",
      providerId,
      email_verified: true,
    });
    const secondTokens = await authB.issueTokensFromProfile({
      email,
      provider: "google",
      providerId,
      email_verified: true,
    });

    const firstPayload = authA.verifyToken(firstTokens.accessToken);
    const secondPayload = authB.verifyToken(secondTokens.accessToken);

    expect(firstPayload?.userId).toBeDefined();
    expect(firstPayload?.userId).not.toBe(providerId);
    expect(secondPayload?.userId).toBe(firstPayload?.userId);
  });

  test("rejects unverified OAuth profiles", async () => {
    const auth = await createAuthenik8({
      jwtSecret: "oauth-secret",
      refreshSecret: "oauth-refresh",
      redis: redisHelper.redis,
    });

    await expect(
      auth.issueTokensFromProfile({
        email: `${redisHelper.namespace}-unverified@example.com`,
        provider: "github",
        providerId: `${redisHelper.namespace}:github`,
        email_verified: false,
      })
    ).rejects.toThrow("OAuth profile email must be verified before issuing tokens");
  });
});
