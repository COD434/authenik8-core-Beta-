import { createAuthenik8 } from "../../createAuthenik8";
import request from "supertest";
import express from "express";
import { createRedisTestHelper, RedisTestHelper } from "../helpers/redisTestHelper";

describe("Refresh Token Concurrency (Integration)", () => {
  let app: express.Express;
  let auth: Awaited<ReturnType<typeof createAuthenik8>>;
  let refreshToken: string;
  let redisHelper: RedisTestHelper;
  const email = "test@test.com";
  let userId: string;

  beforeAll(async () => {
    redisHelper = await createRedisTestHelper("concurrency");
    userId = redisHelper.createUserId("user");

    auth = await createAuthenik8({
      jwtSecret: "test-secret",
      refreshSecret: "refresh-secret",
      jwtExpiry: "15m",
      redis: redisHelper.redis
    });

    app = express();
    app.use(express.json());

    app.post("/login", async (_req, res) => {
      const tokens = await auth.issueTokens({ userId, email });
      refreshToken = tokens.refreshToken;
      res.json({ token: tokens.accessToken, refreshToken });
    });

    app.post("/refresh", async (req, res) => {
      try {
        const result = await auth.refreshToken(req.body.refreshToken);
        res.json(result);
      } catch (err: any) {
        if (err.name === "InvalidTokenError") {
          return res.status(401).json({ error: err.message });
        }

        return res.status(500).json({ error: err.message });
      }
    });
  });

  afterAll(async () => {
    await redisHelper.close();
  });

  it("should allow only one of two concurrent refresh requests", async () => {
    await request(app).post("/login").send({});

    const [res1, res2] = await Promise.all([
      request(app).post("/refresh").send({ refreshToken }),
      request(app).post("/refresh").send({ refreshToken }),
    ]);

    const statuses = [res1.status, res2.status].sort();
    expect(statuses).toEqual([200, 401]);

    const successRes = res1.status === 200 ? res1 : res2;
    expect(successRes.body).toHaveProperty("accessToken");
    expect(successRes.body).toHaveProperty("refreshToken");
  });
});
