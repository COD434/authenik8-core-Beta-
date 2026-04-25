import express from "express";
import request from "supertest";
import { createAuthenik8 } from "../createAuthenik8";
import { createRedisTestHelper } from "./helpers/redisTestHelper";

export const createTestApp = async () => {
  const redisHelper = await createRedisTestHelper("full-integration");
  const user = {
    userId: redisHelper.createUserId("user"),
    email: "test@test.com"
  };

  const auth = await createAuthenik8({
    jwtSecret: "test-secret",
    refreshSecret: "refresh-secret",
    jwtExpiry: "15m",
    redis: redisHelper.redis
  });

  const app = express();
  app.use(express.json());

  app.post("/login", async (_req, res) => {
    const accessToken = auth.signToken(user);
    const refreshToken = await auth.generateRefreshToken(user);

    res.json({ accessToken, refreshToken });
  });

  app.get("/protected", (req, res) => {
    const token = req.headers.authorization?.split(" ")[1];

    if (!token) {
      return res.status(401).json({ error: "Invalid token" });
    }

    try {
      const decoded = auth.verifyToken(token);
      return res.json({ data: "secure data", user: decoded });
    } catch {
      return res.status(401).json({ error: "Unauthorized" });
    }
  });

  app.post("/refresh", async (req, res) => {
    try {
      const result = await auth.refreshToken(req.body.refreshToken);
      res.json(result);
    } catch {
      res.status(401).json({ error: "Invalid refresh token" });
    }
  });

  return { app, auth, request: request(app), redisHelper, user };
};
