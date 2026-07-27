import Redis from "ioredis";
import { createAuthenik8 } from "../../createAuthenik8";
import { createRedisIdentityAdapter } from "../../oauth/adapters/redisAdapter";
import { createIdentityEngine } from "../../oauth/brain/identityEngine";
import { createRedisTestHelper, RedisTestHelper } from "../helpers/redisTestHelper";

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
      jwtSecret: "oauth-secret-32-bytes-minimum-value",
      refreshSecret: "oauth-refresh-32-bytes-minimum-value",
      redis: redisHelper.redis,
      redisKeyPrefix: redisHelper.keyPrefix,
    });
    const authB = await createAuthenik8({
      jwtSecret: "oauth-secret-32-bytes-minimum-value",
      refreshSecret: "oauth-refresh-32-bytes-minimum-value",
      redis: secondaryRedis,
      redisKeyPrefix: redisHelper.keyPrefix,
    });
    const identityPrefix = `${redisHelper.keyPrefix}:oauth:v1`;
    const engineA = createIdentityEngine(
      createRedisIdentityAdapter(redisHelper.redis, identityPrefix),
      {
        issueTokens: authA.issueTokens,
      },
    );
    const engineB = createIdentityEngine(
      createRedisIdentityAdapter(secondaryRedis, identityPrefix),
      {
        issueTokens: authB.issueTokens,
      },
    );

    const firstTokens = await engineA.resolveOAuth({
      mode: "login",
      userId: null,
      profile: {
      email,
      provider: "google",
      providerId,
      email_verified: true,
      },
    }) as any;
    const secondTokens = await engineB.resolveOAuth({
      mode: "login",
      userId: null,
      profile: {
      email,
      provider: "google",
      providerId,
      email_verified: true,
      },
    }) as any;

    const firstPayload = await authA.verifyToken(firstTokens.accessToken);
    const secondPayload = await authB.verifyToken(secondTokens.accessToken);

    expect(firstPayload?.userId).toBeDefined();
    expect(firstPayload?.userId).not.toBe(providerId);
    expect(secondPayload?.userId).toBe(firstPayload?.userId);
  });

  test("does not expose caller-supplied OAuth profile token issuance", async () => {
    const auth = await createAuthenik8({
      jwtSecret: "oauth-secret-32-bytes-minimum-value",
      refreshSecret: "oauth-refresh-32-bytes-minimum-value",
      redis: redisHelper.redis,
      redisKeyPrefix: redisHelper.keyPrefix,
    });

    expect(auth).not.toHaveProperty("issueTokensFromProfile");
  });
});
