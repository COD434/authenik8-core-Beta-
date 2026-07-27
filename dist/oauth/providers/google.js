"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.createGoogleProvider = createGoogleProvider;
const google_auth_library_1 = require("google-auth-library");
const crypto_1 = __importDefault(require("crypto"));
const callback_1 = require("../callback");
const state_1 = require("../state");
const providerSecurity_1 = require("../providerSecurity");
const safeString_1 = require("../../utility/safeString");
const identityValidation_1 = require("../identityValidation");
function createGoogleProvider(config, stateStore, identityEngine, audit) {
    const providerConfig = Object.freeze({ ...config });
    const { clientId } = providerConfig;
    (0, providerSecurity_1.validateOAuthProviderConfig)(providerConfig);
    return {
        redirect: async (req, res, mode = "login") => {
            try {
                const state = crypto_1.default.randomBytes(state_1.OAUTH_STATE_BYTES).toString("hex");
                const userId = (0, providerSecurity_1.authenticatedUserId)(req);
                if (mode === "link" && !userId) {
                    res.status(401).json({ error: "Authentication required for linking" });
                    return;
                }
                await stateStore.set(state, {
                    userId: mode === "link" ? userId : null,
                    mode,
                }, state_1.OAUTH_STATE_TTL_SECONDS);
                await audit?.emit({
                    type: "oauth.state_created",
                    severity: "info",
                    outcome: "success",
                    actor: userId
                        ? { type: "user", id: userId }
                        : { type: "unknown" },
                    metadata: { provider: "google", mode },
                });
                res.redirect(googleAuthorizationUrl(providerConfig, state));
                return;
            }
            catch {
                res.status(500).json({ error: "OAuth redirect failed" });
                return;
            }
        },
        handleCallback: async (req) => {
            const code = (0, providerSecurity_1.readOAuthQueryValue)(req, "code");
            const state = (0, providerSecurity_1.readOAuthQueryValue)(req, "state");
            if (!state) {
                await audit?.emit({
                    type: "oauth.state_rejected",
                    severity: "warning",
                    outcome: "denied",
                    actor: { type: "unknown" },
                    metadata: { provider: "google", reason: "missing" },
                });
                throw new Error("OAuthError:Missing state");
            }
            const stored = await (0, state_1.consumeOAuthState)(stateStore, state);
            if (!stored) {
                await audit?.emit({
                    type: "oauth.state_rejected",
                    severity: "warning",
                    outcome: "denied",
                    actor: { type: "unknown" },
                    metadata: { provider: "google", reason: "invalid_or_expired" },
                });
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
                body: googleTokenRequestBody(providerConfig, code),
                signal: AbortSignal.timeout(providerSecurity_1.OAUTH_HTTP_TIMEOUT_MS),
            });
            if (!tokenRes.ok) {
                throw new Error("OAuthError:Token exchange failed");
            }
            const tokenData = (await (0, providerSecurity_1.readBoundedJsonResponse)(tokenRes));
            const profile = await verifiedGoogleProfile(tokenData, clientId);
            await audit?.emit({
                type: "oauth.state_consumed",
                severity: "info",
                outcome: "success",
                actor: userId
                    ? { type: "user", id: userId }
                    : { type: "unknown" },
                metadata: { provider: "google", mode },
            });
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
    if (typeof tokenData.access_token !== "string" ||
        tokenData.access_token.length === 0 ||
        tokenData.access_token.length > 4096 ||
        (0, safeString_1.containsControlCharacter)(tokenData.access_token)) {
        throw new Error("OAuthError:No access token returned");
    }
    if (typeof tokenData.id_token !== "string" ||
        tokenData.id_token.length === 0 ||
        tokenData.id_token.length > 16 * 1024 ||
        (0, safeString_1.containsControlCharacter)(tokenData.id_token)) {
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
    if (typeof payload.email !== "string" ||
        payload.email.length === 0 ||
        payload.email.length > 254 ||
        (0, safeString_1.containsControlCharacter)(payload.email)) {
        throw new Error("OAuthError:Email not present in ID token");
    }
    if (payload.email_verified !== true) {
        throw new Error("OAuthError:Email not verified");
    }
    if (payload.iss !== "https://accounts.google.com" &&
        payload.iss !== "accounts.google.com") {
        throw new Error("OAuthError: Invalid issuer");
    }
    if (typeof payload.sub !== "string" ||
        payload.sub.length === 0 ||
        payload.sub.length > 512 ||
        (0, safeString_1.containsControlCharacter)(payload.sub)) {
        throw new Error("OAuthError:Invalid subject in ID token");
    }
    return {
        email: (0, identityValidation_1.normalizeIdentityEmail)(payload.email),
        ...(typeof payload.name === "string"
            ? { name: payload.name.slice(0, 512) }
            : {}),
        provider: "google",
        providerId: payload.sub,
        email_verified: true,
    };
};
//# sourceMappingURL=google.js.map