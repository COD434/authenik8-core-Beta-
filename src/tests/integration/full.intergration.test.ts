import { createTestApp } from "../tests/testApp";

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { createAuthenik8 } from '../../createAuthenik8';
import { Authenik8Config } from '../../types/config';
describe("Authenik8 Full Integration", () => {
  let request: any;
  let redisHelper: any;

  let accessToken: string;
  let refreshToken: string;

  beforeAll(async () => {
    const setup = await createTestApp();
    request = setup.request;
    redisHelper = setup.redisHelper;
  });

  afterAll(async () => {
    if (redisHelper) {
      await redisHelper.close();
    }
  });

  test("should login and receive tokens", async () => {
    const res = await request.post("/login");

    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty("accessToken");
    expect(res.body).toHaveProperty("refreshToken");

    accessToken = res.body.accessToken;
    refreshToken = res.body.refreshToken;
  });

  test("should access protected route with valid token", async () => {
    const res = await request
      .get("/protected")
      .set("Authorization", `Bearer ${accessToken}`);

    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty("data", "secure data");
  });

  test("should reject request without token", async () => {
    const res = await request.get("/protected");

    expect(res.status).toBe(401);
  });

  test("should refresh access token", async () => {
    const res = await request
      .post("/refresh")
      .send({ refreshToken });

    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty("accessToken");
    expect(res.body).toHaveProperty("refreshToken");

    accessToken = res.body.accessToken;
    refreshToken = res.body.refreshToken;
  });

  test("should NOT allow reuse of old refresh token", async () => {
    const originalToken = refreshToken;

    const firstRes = await request
      .post("/refresh")
      .send({ refreshToken: originalToken });

    expect(firstRes.status).toBe(200);

    const newToken = firstRes.body.refreshToken;

    const res = await request
      .post("/refresh")
      .send({ refreshToken: originalToken });

    expect(res.status).toBe(401);

    const validRes = await request
      .post("/refresh")
      .send({ refreshToken: newToken });

    expect(validRes.status).toBe(200);
  });

});
