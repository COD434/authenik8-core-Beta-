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
      jwtSecret: "oauth-secret",
      refreshSecret: "oauth-refresh",
      redis: redisHelper.redis,
    });
    const authB = await createAuthenik8({
      jwtSecret: "oauth-secret",
      refreshSecret: "oauth-refresh",
      redis: secondaryRedis,
    });
    const engineA = createIdentityEngine(createRedisIdentityAdapter(redisHelper.redis), {
      signAccessToken: authA.signToken,
      generateRefreshToken: authA.generateRefreshToken,
    });
    const engineB = createIdentityEngine(createRedisIdentityAdapter(secondaryRedis), {
      signAccessToken: authB.signToken,
      generateRefreshToken: authB.generateRefreshToken,
    });

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

    const firstPayload = authA.verifyToken(firstTokens.accessToken);
    const secondPayload = authB.verifyToken(secondTokens.accessToken);

    expect(firstPayload?.userId).toBeDefined();
    expect(firstPayload?.userId).not.toBe(providerId);
    expect(secondPayload?.userId).toBe(firstPayload?.userId);
  });

  test("does not expose caller-supplied OAuth profile token issuance", async () => {
    const auth = await createAuthenik8({
      jwtSecret: "oauth-secret",
      refreshSecret: "oauth-refresh",
      redis: redisHelper.redis,
    });

    expect(auth).not.toHaveProperty("issueTokensFromProfile");
  });
});
