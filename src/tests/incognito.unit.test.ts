import express from "express";
import request from "supertest";
import jwt from "jsonwebtoken";
import { createIncognito } from "../auth/guestModeService";

describe("createIncognito", () => {
  const jwtSecret = "incognito-unit-secret";

  const createApp = () => {
    const app = express();
    app.get(
      "/session",
      createIncognito({
        jwtSecret,
        guestToken: () =>
          jwt.sign(
            {
              type: "guest-mode",
              id: "guest-id",
              createdAt: Date.now(),
            },
            jwtSecret,
            { expiresIn: "15m" }
          ),
      }),
      (req, res) => {
        res.json({ user: (req as any).user });
      }
    );

    return app;
  };

  test("issues a signed guest token when no bearer token is present", async () => {
    const response = await request(createApp()).get("/session");

    expect(response.status).toBe(200);
    expect(response.headers["x-guest-token"]).toBeDefined();
    expect(response.body.user.type).toBe("guest-mode");
  });

  test("accepts a valid authenticated bearer token", async () => {
    const token = jwt.sign(
      {
        userId: "user-1",
        email: "user@example.com",
        role: "user",
      },
      jwtSecret,
      { expiresIn: "15m" }
    );

    const response = await request(createApp())
      .get("/session")
      .set("Authorization", `Bearer ${token}`);

    expect(response.status).toBe(200);
    expect(response.body.user.userId).toBe("user-1");
    expect(response.body.user.type).toBe("authenticated");
  });

  test("rejects invalid bearer tokens", async () => {
    const response = await request(createApp())
      .get("/session")
      .set("Authorization", "Bearer not-a-real-token");

    expect(response.status).toBe(401);
  });
});
