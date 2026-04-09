import dotenv from "dotenv";
import express, { Request, Response, NextFunction } from "express";
import { createAuthenik8 } from "../createAuthenik8";
import { TokenPayload } from "../types/tokens";
import { createIdentityEngine } from "../oauth/brain/identityEngine";
import { memoryAdapter } from "../oauth/adapters/memoryAdapter";

dotenv.config();
  
const app = express();

// =========================
// TOKEN SERVICE (TEST)
// =========================
const tokenService = {
  signAccessToken: (payload: any) => {
    return `test_access_token_${payload.userId}`;
  },
  generateRefreshToken: async (payload: any) => {
    return `test_refresh_token_${payload.userId}`;
  },
};

const identityEngine = createIdentityEngine(memoryAdapter, tokenService);

// =========================
// AUTH INIT
// =========================
async function start() {
  const auth = await createAuthenik8({
    jwtSecret: "test",
    refreshSecret: "test",
    oauth: {
      google: {
        clientId: process.env.GOOGLE_CLIENT_ID!,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
        redirectUri: "http://localhost:4000/callback",
      },
      github: {
        clientId: process.env.GITHUB_CLIENT_ID!,
        clientSecret: process.env.GITHUB_CLIENT_SECRET!,
        redirectUri: "http://localhost:4000/auth/github/callback",
      },
    },
  });

  // =========================
  // AUTH MIDDLEWARE
  // =========================
  function requireAuth(req: Request, res: Response, next: NextFunction) {
    const token = req.headers.authorization?.split(" ")[1];

    if (!token) return res.status(401).json({ error: "Unauthorized" });

    try {
      req.user = auth.verifyToken(token);
      next();
    } catch {
      return res.status(401).json({ error: "Invalid token" });
    }
  }

  // =====================================================
  // STEP 1: GOOGLE LOGIN (CREATE USER)
  // =====================================================
  app.get("/auth/google", (req, res) => {
    auth.oauth!.google!.redirect(req, res);
  });

  app.get("/callback", async (req, res) => {
    try {
      const { profile, mode, userId } =
        await auth.oauth!.google!.handleCallback(req);

      const result = await identityEngine.resolveOAuth({
        profile,
        mode,
        userId,
      });

      return res.json({
        step: "google-login",
        ...result,
      });
    } catch (err) {
      return res.status(500).json({
        error: err instanceof Error ? err.message : "Unknown error",
      });
    }
  });

  // =====================================================
  // STEP 2: GITHUB LOGIN (SEPARATE LOGIN FLOW)
  // =====================================================
  app.get("/auth/github", (req, res) => {
    auth.oauth!.github!.redirect(req, res);
  });

  app.get("/auth/github/callback", async (req, res) => {
    try {
      const { profile, mode, userId } =
        await auth.oauth!.github!.handleCallback(req);

      const result = await identityEngine.resolveOAuth({
        profile,
        mode,
        userId,
      });

      return res.json({
        step: "github-login",
        ...result,
      });
    } catch (err) {
      return res.status(500).json({
        error: err instanceof Error ? err.message : "Unknown error",
      });
    }
  });

  // =====================================================
  // STEP 3: GITHUB LINK FLOW (LINK TO SAME USER)
  // =====================================================
  app.get("/auth/github/link", requireAuth, (req, res) => {
    auth.oauth!.github!.redirect(req, res);
  });

  app.get("/auth/github/link/callback", requireAuth, async (req, res) => {
    try {
      const { profile, mode } =
        await auth.oauth!.github!.handleCallback(req);

      const result = await identityEngine.resolveOAuth({
        profile,
        mode: "link",
        userId: req.user!.userId,
      });

      return res.json({
        step: "github-link",
        ...result,
      });
    } catch (err) {
      return res.status(400).json({
        error: err instanceof Error ? err.message : "Linking error",
      });
    }
  });
}

// =========================
// START SERVER
// =========================
start().then(() => {
  app.listen(4000, () => {
    console.log("OAuth test server running on http://localhost:4000");
  });
});
