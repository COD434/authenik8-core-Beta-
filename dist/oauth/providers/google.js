"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.createGoogleProvider = createGoogleProvider;
const google_auth_library_1 = require("google-auth-library");
const crypto_1 = __importDefault(require("crypto"));
function createGoogleProvider(config, redisClient, identityEngine) {
    const { clientId, clientSecret, redirectUri } = config;
    return {
        redirect: async (req, res) => {
            var _a, _b;
            try {
                const state = crypto_1.default.randomBytes(32).toString("hex");
                const mode = req.path.includes("link") ? "link" : "login";
                const authUser = (_a = req.user) !== null && _a !== void 0 ? _a : null;
                await redisClient.setex(`oauth:state:${state}`, 300, JSON.stringify({
                    userId: (_b = authUser === null || authUser === void 0 ? void 0 : authUser.userId) !== null && _b !== void 0 ? _b : null,
                    mode,
                }));
                const url = new URL("https://accounts.google.com/o/oauth2/v2/auth");
                url.searchParams.set("client_id", clientId);
                url.searchParams.set("redirect_uri", redirectUri);
                url.searchParams.set("response_type", "code");
                url.searchParams.set("scope", "openid email profile");
                url.searchParams.set("access_type", "offline");
                url.searchParams.set("prompt", "consent");
                url.searchParams.set("state", state);
                res.redirect(url.toString());
                return;
            }
            catch (err) {
                console.error("Google redirect error:", err);
                res.status(500).json({ error: "OAuth redirect failed" });
                return;
            }
        },
        handleCallback: async (req) => {
            const code = req.query.code;
            const client = new google_auth_library_1.OAuth2Client(clientId);
            const state = req.query.state;
            if (!state) {
                throw new Error("OAuthError:Missing state");
            }
            const stored = await redisClient.get(`oauth:state:${state}`);
            if (!stored) {
                throw new Error("OAuthError:Invalid or expired state");
            }
            const { userId, mode } = JSON.parse(stored);
            if (!code) {
                throw new Error("OauthError:Missing authorization code");
            }
            const params = new URLSearchParams();
            params.append("client_id", clientId);
            params.append("client_secret", clientSecret);
            params.append("code", code);
            params.append("grant_type", "authorization_code");
            params.append("redirect_uri", redirectUri);
            // 1. Exchange code for tokens
            const tokenRes = await fetch("https://oauth2.googleapis.com/token", {
                method: "POST",
                headers: {
                    "Content-Type": "application/x-www-form-urlencoded",
                },
                body: params
            });
            if (!tokenRes.ok) {
                const err = await tokenRes.text();
                throw new Error(`OAuthError:Token exchange failed->${err}`);
            }
            const tokenData = await tokenRes.json();
            if (!tokenData.access_token) {
                throw new Error("OAuthError:No access token returned");
            }
            if (!tokenData.id_token) {
                console.log("TOKEN DATA:", tokenData);
                throw new Error("OAuthError:No id_token returned from Google");
            }
            const ticket = await client.verifyIdToken({
                idToken: tokenData.id_token,
                audience: clientId,
            });
            const payload = ticket.getPayload();
            if (!payload) {
                throw new Error("OAuthError:Invalid ID token payload");
            }
            if (!payload.email) {
                throw new Error("OAuthError:Email not present in ID token");
            }
            if (!payload.email_verified) {
                throw new Error("OAuthError:Email not verified");
            }
            if (payload.iss !== "https://accounts.google.com" &&
                payload.iss !== "accounts.google.com") {
                throw new Error("OAuthError: Invalid issuer");
            }
            const profile = {
                email: payload.email,
                name: payload.name,
                provider: "google",
                providerId: payload.sub,
            };
            const accessToken = tokenData.access_token;
            console.log("Token data:", tokenData);
            console.log("[OAuth] Fetching user profile...");
            console.log("FINAL ENGINE INPUT:", {
                profile,
                mode,
                userId,
            });
            let result;
            try {
                result = await identityEngine.resolveOAuth({
                    profile,
                    mode,
                    userId,
                });
            }
            catch (err) {
                console.error("ENGINE ERROR:", err);
                throw err;
            }
            if (result.type !== "INVALID_LINK_REQUEST" &&
                result.type !== "EXISTING_EMAIL_CONFLICT" &&
                !result.user) {
                throw new Error("Invalid engine result: missing user");
            }
            await redisClient.del(`oauth:state:${state}`);
            return {
                profile,
                mode,
                userId,
            };
        }
    };
}
//# sourceMappingURL=google.js.map