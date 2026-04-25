import dotenv from "dotenv";
import express, { Request, Response, NextFunction } from "express";
import { createAuthenik8 } from "../createAuthenik8";
import { TokenPayload } from "../types/tokens";
import { createIdentityEngine } from "../oauth/brain/identityEngine";
import { memoryAdapter } from "../oauth/adapters/memoryAdapter";

const tokenService = {
  signAccessToken: () => "test_access_token",
  generateRefreshToken: async () => "test_refresh_token",
};
const identityEngine = createIdentityEngine(memoryAdapter,tokenService);

dotenv.config();

const app = express();

declare global {
  namespace Express {
    interface Request {
      user?: TokenPayload;
    }
  }
}

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

  // =========================
  // GOOGLE LOGIN
  // =========================

  app.get("/auth/google", (req, res) => {
    auth.oauth!.google!.redirect(req, res);
  });

  app.get("/callback", async (req, res) => {
    try {
      const {profile,mode, userId} = await auth.oauth!.google!.handleCallback(req);

      console.log("ENGINE INPUT:", {
      mode,
      userId,
    });
    const result = await identityEngine.resolveOAuth({
      profile,
      mode,
      userId,
    });

      return res.json({
        provider: "google",
        message: "Google login successful",
        ...result,
      });

    } catch (err) {
      return res.status(500).json({
        error: err instanceof Error ? err.message : "Unknown error",
      });
    }
  });

  // =========================
  // GITHUB LOGIN
  // =========================

  app.get("/auth/github", (req, res) => {
    auth.oauth!.github!.redirect(req, res);
  });

  app.get("/auth/github/callback", async (req, res) => {
    try {
      const result = await auth.oauth!.github!.handleCallback(req);

      return res.json({
        provider: "github",
        message: "GitHub login successful",
        ...result,
      });
    } catch (err) {
      return res.status(500).json({
        error: err instanceof Error ? err.message : "Unknown error",
      });
    }
  });

  // =========================
  // LINK FLOW (GITHUB)
  // =========================

  app.get("/auth/github/link", requireAuth, (req, res) => {
    auth.oauth!.github!.redirect(req, res);
  });

  app.get("/auth/github/link/callback", requireAuth, async (req, res) => {
    try {
      const result = await auth.oauth!.github!.handleCallback(req);

      return res.json({
        provider: "github",
        message: "GitHub account linked successfully",
        ...result,
      });
    } catch (err) {
      return res.status(400).json({
        error: err instanceof Error ? err.message : "Linking error",
      });
    }
  });
}

start().then(() => {
  app.listen(4000, () => {
    console.log("OAuth test server running on http://localhost:4000");
  });
});
