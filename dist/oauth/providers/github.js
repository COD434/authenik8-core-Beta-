"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.createGitHubProvider = createGitHubProvider;
const crypto_1 = __importDefault(require("crypto"));
const callback_1 = require("../callback");
function createGitHubProvider(config, stateStore, identityEngine) {
    return {
        redirect: async (req, res, mode = "login") => {
            if (res.headersSent) {
                return;
            }
            const state = crypto_1.default.randomBytes(32).toString("hex");
            const authUser = req.user ?? null;
            await stateStore.set(state, {
                userId: authUser?.userId ?? null,
                mode,
            }, 300);
            res.redirect(githubAuthorizationUrl(config, state));
            return;
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
                throw new Error("OAuthError: Missing code");
            }
            const accessToken = await fetchGithubAccessToken(config, code);
            const profile = await verifiedGitHubProfile(accessToken);
            await stateStore.del(state);
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
    });
    const tokenData = (await tokenRes.json());
    if (!tokenData.access_token) {
        throw new Error("OAuthError: No access token from Github");
    }
    return tokenData.access_token;
};
const verifiedGitHubProfile = async (accessToken) => {
    const userRes = await fetch("https://api.github.com/user", {
        headers: {
            Authorization: `Bearer ${accessToken}`,
        },
    });
    if (!userRes.ok) {
        throw new Error("OAuthError: Failed to fetch GitHub user");
    }
    const userData = (await userRes.json());
    const emailRes = await fetch("https://api.github.com/user/emails", {
        headers: {
            Authorization: `Bearer ${accessToken}`,
        },
    });
    const emails = (await emailRes.json());
    const primaryEmail = emails.find((email) => email.primary && email.verified)
        ?.email;
    if (!primaryEmail) {
        throw new Error("OAuthError: No verified primary email found");
    }
    return {
        email: primaryEmail,
        name: userData.name,
        provider: "github",
        providerId: userData.id.toString(),
        email_verified: true,
    };
};
//# sourceMappingURL=github.js.map