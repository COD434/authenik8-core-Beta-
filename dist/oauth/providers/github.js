"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.createGitHubProvider = createGitHubProvider;
const crypto_1 = __importDefault(require("crypto"));
const callback_1 = require("../callback");
const state_1 = require("../state");
const providerSecurity_1 = require("../providerSecurity");
const safeString_1 = require("../../utility/safeString");
const identityValidation_1 = require("../identityValidation");
function createGitHubProvider(config, stateStore, identityEngine, audit) {
    const providerConfig = Object.freeze({ ...config });
    (0, providerSecurity_1.validateOAuthProviderConfig)(providerConfig);
    if (providerConfig.enterprise) {
        throw new Error("GitHub Enterprise OAuth requires explicit trusted endpoint configuration and is not supported by this adapter");
    }
    return {
        redirect: async (req, res, mode = "login") => {
            if (res.headersSent) {
                return;
            }
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
                metadata: { provider: "github", mode },
            });
            res.redirect(githubAuthorizationUrl(providerConfig, state));
            return;
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
                    metadata: { provider: "github", reason: "missing" },
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
                    metadata: { provider: "github", reason: "invalid_or_expired" },
                });
                throw new Error("OAuthError:Invalid or expired state");
            }
            const { userId, mode } = stored;
            if (!code) {
                throw new Error("OAuthError: Missing code");
            }
            const accessToken = await fetchGithubAccessToken(providerConfig, code);
            const profile = await verifiedGitHubProfile(accessToken);
            await audit?.emit({
                type: "oauth.state_consumed",
                severity: "info",
                outcome: "success",
                actor: userId
                    ? { type: "user", id: userId }
                    : { type: "unknown" },
                metadata: { provider: "github", mode },
            });
            return (0, callback_1.finalizeOAuthCallback)(profile, mode, userId, identityEngine);
        },
    };
}
const githubAuthorizationUrl = (config, state) => {
    const url = new URL("https://github.com/login/oauth/authorize");
    url.searchParams.set("client_id", config.clientId);
    url.searchParams.set("redirect_uri", config.redirectUri);
    url.searchParams.set("scope", "read:user user:email");
    url.searchParams.set("state", state);
    return url.toString();
};
const fetchGithubAccessToken = async (config, code) => {
    const params = new URLSearchParams();
    params.append("client_id", config.clientId);
    params.append("client_secret", config.clientSecret);
    params.append("code", code);
    const tokenRes = await fetch("https://github.com/login/oauth/access_token", {
        method: "POST",
        headers: {
            Accept: "application/json",
        },
        body: params,
        signal: AbortSignal.timeout(providerSecurity_1.OAUTH_HTTP_TIMEOUT_MS),
    });
    if (!tokenRes.ok) {
        throw new Error("OAuthError: GitHub token exchange failed");
    }
    const tokenData = (await (0, providerSecurity_1.readBoundedJsonResponse)(tokenRes));
    if (typeof tokenData.access_token !== "string" ||
        tokenData.access_token.length === 0 ||
        tokenData.access_token.length > 4096 ||
        (0, safeString_1.containsControlCharacter)(tokenData.access_token)) {
        throw new Error("OAuthError: No access token from Github");
    }
    return tokenData.access_token;
};
const verifiedGitHubProfile = async (accessToken) => {
    const userRes = await fetch("https://api.github.com/user", {
        headers: {
            Authorization: `Bearer ${accessToken}`,
            Accept: "application/vnd.github+json",
        },
        signal: AbortSignal.timeout(providerSecurity_1.OAUTH_HTTP_TIMEOUT_MS),
    });
    if (!userRes.ok) {
        throw new Error("OAuthError: Failed to fetch GitHub user");
    }
    const userValue = await (0, providerSecurity_1.readBoundedJsonResponse)(userRes);
    if (!userValue ||
        typeof userValue !== "object" ||
        !Number.isSafeInteger(userValue.id) ||
        userValue.id <= 0) {
        throw new Error("OAuthError: Invalid GitHub user identifier");
    }
    const userData = userValue;
    const emailRes = await fetch("https://api.github.com/user/emails", {
        headers: {
            Authorization: `Bearer ${accessToken}`,
            Accept: "application/vnd.github+json",
        },
        signal: AbortSignal.timeout(providerSecurity_1.OAUTH_HTTP_TIMEOUT_MS),
    });
    if (!emailRes.ok) {
        throw new Error("OAuthError: Failed to fetch GitHub emails");
    }
    const emailsValue = await (0, providerSecurity_1.readBoundedJsonResponse)(emailRes);
    if (!Array.isArray(emailsValue) || emailsValue.length > 100) {
        throw new Error("OAuthError: Invalid GitHub email response");
    }
    const emails = emailsValue;
    const primaryEmail = emails.find((email) => !!email &&
        typeof email === "object" &&
        email.primary === true &&
        email.verified === true &&
        typeof email.email === "string")?.email;
    if (typeof primaryEmail !== "string" ||
        primaryEmail.length === 0 ||
        primaryEmail.length > 254 ||
        (0, safeString_1.containsControlCharacter)(primaryEmail)) {
        throw new Error("OAuthError: No verified primary email found");
    }
    return {
        email: (0, identityValidation_1.normalizeIdentityEmail)(primaryEmail),
        ...(typeof userData.name === "string"
            ? { name: userData.name.slice(0, 512) }
            : {}),
        provider: "github",
        providerId: userData.id.toString(),
        email_verified: true,
    };
};
//# sourceMappingURL=github.js.map