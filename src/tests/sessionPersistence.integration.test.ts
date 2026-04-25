import { createAuthenik8 } from "../createAuthenik8";
import { createRedisTestHelper, RedisTestHelper } from "./helpers/redisTestHelper";

const waitForValue = async (
  lookup: () => Promise<string | null>,
  timeoutMs = 1500
): Promise<string | null> => {
  const deadline = Date.now() + timeoutMs;

  while (Date.now() < deadline) {
    const value = await lookup();
    if (value) {
      return value;
    }

    await new Promise((resolve) => setTimeout(resolve, 25));
  }

  return null;
};

describe("session persistence", () => {
  let redisHelper: RedisTestHelper;

  beforeAll(async () => {
    redisHelper = await createRedisTestHelper("session-persistence");
  });

  afterAll(async () => {
    await redisHelper.close();
  });

  test("signToken persists the active access token session", async () => {
    const auth = await createAuthenik8({
      jwtSecret: "session-secret",
      refreshSecret: "refresh-secret",
      redis: redisHelper.redis,
    });
    const payload = {
      userId: redisHelper.createUserId("session-user"),
      email: "session@example.com",
      role: "user",
    };

    const token = auth.signToken(payload);
    const stored = await waitForValue(() =>
      redisHelper.redis.get(`session:${payload.userId}`)
    );

    expect(stored).toBe(token);
  });
});
