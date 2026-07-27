import { createAuthenik8 } from "../../createAuthenik8";
import { createRedisTestHelper, RedisTestHelper } from "../helpers/redisTestHelper";

const waitForValue = async (
  lookup: () => Promise<Record<string , string>>,
  timeoutMs = 1500
)=> {
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
      jwtSecret: "session-secret-32-bytes-minimum-value",
      refreshSecret: "refresh-secret-32-bytes-minimum-value",
      redis: redisHelper.redis,
      redisKeyPrefix: redisHelper.keyPrefix,
    });
    const payload = {
      userId: redisHelper.createUserId("sessions"),
      email: "session@example.com",
     role: "user",
    };
	    const token = await auth.signToken(payload);
	    const stored = await waitForValue(() =>
	      redisHelper.redis.hgetall(
          `${redisHelper.keyPrefix}:sessions:${payload.userId}`,
        )
	    );
	    
    const sessions = Object.values(stored!);
    const parsed = sessions.map((session) => JSON.parse(session));
    expect(parsed).toContainEqual(
      expect.objectContaining({ tokenHash: expect.any(String) }),
    );
    expect(parsed.every((session) => session.token === undefined)).toBe(true);
    await expect(auth.verifyActiveToken(token)).resolves.toMatchObject({
      userId: payload.userId,
    });
  });
});
