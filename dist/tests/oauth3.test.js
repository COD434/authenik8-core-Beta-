"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const dotenv_1 = __importDefault(require("dotenv"));
const express_1 = __importDefault(require("express"));
const createAuthenik8_1 = require("../createAuthenik8");
const identityEngine_1 = require("../oauth/brain/identityEngine");
const memoryAdapter_1 = require("../oauth/adapters/memoryAdapter");
dotenv_1.default.config();
const app = (0, express_1.default)();
app.use(express_1.default.json());
// =========================
// TOKEN SERVICE (TEST)
// =========================
const tokenService = {
    signAccessToken: (payload) => `test_access_${payload.userId}`,
    generateRefreshToken: async (payload) => `test_refresh_${payload.userId}`,
};
const identityEngine = (0, identityEngine_1.createIdentityEngine)(memoryAdapter_1.memoryAdapter, tokenService);
// =========================
// SIMPLE AUTH PARSER (NO req.user TYPE ISSUES)
// =========================
function getUserFromHeader(req) {
    const header = req.headers["x-user-id"];
    if (!header)
        return null;
    return {
        userId: header,
    };
}
// =========================
// INIT AUTH
// =========================
async function start() {
    const auth = await (0, createAuthenik8_1.createAuthenik8)({
        jwtSecret: "test",
        refreshSecret: "test",
        oauth: {
            google: {
                clientId: process.env.GOOGLE_CLIENT_ID,
                clientSecret: process.env.GOOGLE_CLIENT_SECRET,
                redirectUri: "http://localhost:4000/callback",
            },
            github: {
                clientId: process.env.GITHUB_CLIENT_ID,
                clientSecret: process.env.GITHUB_CLIENT_SECRET,
                redirectUri: "http://localhost:4000/auth/github/callback",
            },
        },
    });
    // =====================================================
    // STEP 1: GOOGLE LOGIN (CREATE USER)
    // =====================================================
    app.get("/auth/google", (req, res) => {
        auth.oauth.google.redirect(req, res);
    });
    app.get("/callback", async (req, res) => {
        try {
            const { profile, mode, userId } = await auth.oauth.google.handleCallback(req);
            const result = await identityEngine.resolveOAuth({
                profile,
                mode,
                userId,
            });
            return res.json({
                step: "google-login",
                ...result,
            });
        }
        catch (err) {
            return res.status(500).json({
                error: err instanceof Error ? err.message : "Unknown error",
            });
        }
    });
    // =====================================================
    // STEP 2: GITHUB LOGIN (DIRECT LOGIN)
    // =====================================================
    app.get("/auth/github", (req, res) => {
        console.log("🔥 HIT /auth/github");
        auth.oauth.github.redirect(req, res);
        return;
    });
    app.get("/auth/github/callback", async (req, res) => {
        try {
            const { profile, mode, userId } = await auth.oauth.github.handleCallback(req);
            const result = await identityEngine.resolveOAuth({
                profile,
                mode,
                userId,
            });
            return res.json({
                step: "github-login",
                ...result,
            });
        }
        catch (err) {
            return res.status(500).json({
                error: err instanceof Error ? err.message : "Unknown error",
            });
        }
    });
    // =====================================================
    // STEP 3: LINK GITHUB TO EXISTING USER (NO req.user)
    // =====================================================
    app.get("/auth/github/link", (req, res) => {
        // auth.oauth!.github!.redirect(req, res);
        console.log("🔥 HIT /auth/github/link");
        const user = getUserFromHeader(req); // ✅ REQUIRED HERE
        if (!user) {
            return res.status(401).json({ error: "Unauthorized" });
        }
        req.user = user;
        auth.oauth.github.redirect(req, res, "link");
        return;
    });
    app.get("/auth/github/link/callback", async (req, res) => {
        try {
            const { profile, mode, userId } = await auth.oauth.github.handleCallback(req);
            const result = await identityEngine.resolveOAuth({
                profile,
                mode,
                userId,
            });
            return res.json({
                step: "github-link",
                ...result,
            });
        }
        catch (err) {
            return res.status(400).json({
                error: err instanceof Error ? err.message : "Link error",
            });
        }
    });
}
// =========================
// START SERVER
// =========================
console.log("USERS:", memoryAdapter_1.memoryAdapter.dump());
start().then(() => {
    app.listen(4000, () => {
        console.log("OAuth test running on http://localhost:4000");
    });
});
//# sourceMappingURL=oauth3.test.js.map