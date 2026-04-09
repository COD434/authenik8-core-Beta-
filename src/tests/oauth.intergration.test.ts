import request from "supertest";
import express from "express";
import { createAuthenik8 } from "../createAuthenik8";

test("OAuth callback issues tokens", async () => {
  const app = express();

  const auth = await createAuthenik8({
    jwtSecret: "test",
    refreshSecret: "test",
  });

  // 🔥 Mock OAuth provider
  auth.oauth = {
    google: {
      handleCallback: async () => ({
        profile: {
          email: "test@example.com",
          name: "Test User",
          provider: "google",
          providerId: "123",
        },
      }),
    },
  } as any;

  app.get("/callback", async (req, res) => {
    const { profile } = await auth.oauth!.google!.handleCallback(req);
    const tokens = await auth.issueTokensFromProfile(profile);

    res.json(tokens);
  });

  const res = await request(app).get("/callback");

  expect(res.status).toBe(200);
  expect(res.body.accessToken).toBeDefined();
  expect(res.body.refreshToken).toBeDefined();
});
