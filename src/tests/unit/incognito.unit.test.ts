import express from "express";
import request from "supertest";
import { beforeEach, describe, expect, it } from "vitest";
import { createIncognito } from "../../auth/guestModeService";
import { JWTService } from "../../auth/jwtAuth";

const SECRET = "incognito-unit-secret-32-bytes-minimum";

describe("createIncognito", () => {
  let tokens: JWTService;

  beforeEach(() => {
    tokens = new JWTService({ jwtSecret: SECRET, expiry: "15m" });
  });

  const createApp = () => {
    const app = express();
    app.get(
      "/session",
      createIncognito({
        guestToken: tokens.guestToken.bind(tokens),
        verifyAccessToken: tokens.verifyToken.bind(tokens),
        verifyGuestToken: tokens.verifyGuestToken.bind(tokens),
      }),
      (req, res) => res.json({ user: (req as any).user }),
    );
    return app;
  };

  it("issues and verifies a purpose-bound guest token", async () => {
    const response = await request(createApp()).get("/session");
    expect(response.status).toBe(200);
    expect(response.headers["x-guest-token"]).toBeDefined();
    expect(response.body.user.tokenUse).toBe("guest");
  });

  it("accepts a purpose-bound authenticated bearer token", async () => {
    const token = await tokens.signToken({
      userId: "user-1",
      email: "user@example.com",
      role: "user",
    });
    const response = await request(createApp())
      .get("/session")
      .set("Authorization", `Bearer ${token}`);

    expect(response.status).toBe(200);
    expect(response.body.user).toMatchObject({
      userId: "user-1",
      type: "authenticated",
      tokenUse: "access",
    });
  });

  it("rejects malformed and wrong-purpose bearer tokens", async () => {
    await request(createApp())
      .get("/session")
      .set("Authorization", "Basic invalid")
      .expect(401);
    const guest = await tokens.guestToken();
    await request(createApp())
      .get("/session")
      .set("Authorization", `Bearer ${guest}`)
      .expect(401);
  });
});
