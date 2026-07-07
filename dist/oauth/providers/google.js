"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.createGoogleProvider = createGoogleProvider;
const google_auth_library_1 = require("google-auth-library");
const crypto_1 = __importDefault(require("crypto"));
const callback_1 = require("../callback");
function createGoogleProvider(config, stateStore, identityEngine) {
    const { clientId, clientSecret, redirectUri } = config;
    return {
        redirect: async (req, res) => {
            try {
                const state = crypto_1.default.randomBytes(32).toString("hex");
                const mode = req.path.includes("link") ? "link" : "login";
                const authUser = req.user ?? null;
                await stateStore.set(state, {
                    userId: authUser?.userId ?? null,
                    mode,
                }, 300);
                res.redirect(googleAuthorizationUrl(config, state));
                return;
            }
            catch {
                res.status(500).json({ error: "OAuth redirect failed" });
                return;
            }
        },
        handleCallback: async (req) => {
            const code = req.query.code;
            const state = req.query.state;
            if (!state) {
                throw new Error("OAuthError:Missing state");
            }
            const stored = await stateStore.get(state);
            if (!stored) {
                throw new Error("OAuthError:Invalid or expired state");
            }
            const { userId, mode } = stored;
            if (!code) {
                throw new Error("OauthError:Missing authorization code");
            }
            const tokenRes = await fetch("https://oauth2.googleapis.com/token", {
                method: "POST",
                headers: {
                    "Content-Type": "application/x-www-form-urlencoded",
                },
                body: googleTokenRequestBody(config, code),
            });
            if (!tokenRes.ok) {
                const err = await tokenRes.text();
                throw new Error(`OAuthError:Token exchange failed->${err}`);
            }
            const tokenData = (await tokenRes.json());
            const profile = await verifiedGoogleProfile(tokenData, clientId);
            await stateStore.del(state);
            return (0, callback_1.finalizeOAuthCallback)(profile, mode, userId, identityEngine);
        },
    };
}
const googleAuthorizationUrl = (config, state) => {
    const url = new URL("https://accounts.google.com/o/oauth2/v2/auth");
    url.searchParams.set("client_id", config.clientId);
    url.searchParams.set("redirect_uri", config.redirectUri);
    url.searchParams.set("response_type", "code");
    url.searchParams.set("scope", "openid email profile");
    url.searchParams.set("access_type", "offline");
    url.searchParams.set("prompt", "consent");
    url.searchParams.set("state", state);
    return url.toString();
};
const googleTokenRequestBody = (config, code) => {
    const params = new URLSearchParams();
    params.append("client_id", config.clientId);
    params.append("client_secret", config.clientSecret);
    params.append("code", code);
    params.append("grant_type", "authorization_code");
    params.append("redirect_uri", config.redirectUri);
    return params;
};
const verifiedGoogleProfile = async (tokenData, clientId) => {
    if (!tokenData.access_token) {
        throw new Error("OAuthError:No access token returned");
    }
    if (!tokenData.id_token) {
        throw new Error("OAuthError:No id_token returned from Google");
    }
    const client = new google_auth_library_1.OAuth2Client(clientId);
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
    return {
        email: payload.email,
        name: payload.name,
        provider: "google",
        providerId: payload.sub,
        email_verified: payload.email_verified ?? false,
    };
};
//# sourceMappingURL=google.js.map