"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.createGitHubProvider = createGitHubProvider;
const crypto_1 = __importDefault(require("crypto"));
function createGitHubProvider(config, redisClient, identityEngine) {
    const { clientId, clientSecret, redirectUri } = config;
    return {
        redirect: async (req, res, mode = "login") => {
            var _a, _b;
            if (res.headersSent) {
                console.log("🚨 HEADERS ALREADY SENT — SKIPPING");
                return;
            }
            const state = crypto_1.default.randomBytes(32).toString("hex");
            const authUser = (_a = req.user) !== null && _a !== void 0 ? _a : null;
            await redisClient.setex(`oauth:state:${state}`, 300, JSON.stringify({
                userId: (_b = authUser === null || authUser === void 0 ? void 0 : authUser.userId) !== null && _b !== void 0 ? _b : null,
                mode,
            }));
            const url = new URL("https://github.com/login/oauth/authorize");
            url.searchParams.set("client_id", clientId);
            url.searchParams.set("redirect_uri", redirectUri);
            url.searchParams.set("scope", "read:user user:email");
            url.searchParams.set("state", state);
            console.log("REDIRECT STATE:", {
                userId: authUser === null || authUser === void 0 ? void 0 : authUser.userId,
                mode,
            });
            res.redirect(url.toString());
            return;
        },
        handleCallback: async (req) => {
            var _a;
            const code = req.query.code;
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
                throw new Error("OAuthError: Missing code");
            }
            const params = new URLSearchParams();
            params.append("client_id", clientId);
            params.append("client_secret", clientSecret);
            params.append("code", code);
            const tokenRes = await fetch("https://github.com/login/oauth/access_token", {
                method: "POST",
                headers: {
                    Accept: "application/json",
                },
                body: params,
            });
            const tokenData = await tokenRes.json();
            if (!tokenData.access_token) {
                throw new Error("OAuthError: No access token from Github");
            }
            const accessToken = tokenData.access_token;
            const userRes = await fetch("https://api.github.com/user", {
                headers: {
                    Authorization: `Bearer  ${accessToken}`,
                },
            });
            if (!userRes.ok) {
                throw new Error("OAuthError: Failed to fetch GitHub user");
            }
            const userData = await userRes.json();
            const emailRes = await fetch("https://api.github.com/user/emails", {
                headers: {
                    Authorization: `Bearer ${accessToken}`,
                },
            });
            const emails = await emailRes.json();
            const primaryEmail = (_a = emails.find((e) => e.primary)) === null || _a === void 0 ? void 0 : _a.email;
            if (!primaryEmail) {
                throw new Error("OAuthError: No primary email  found");
            }
            const profile = {
                email: primaryEmail,
                name: userData.name,
                provider: "github",
                providerId: userData.id.toString(),
            };
            await redisClient.del(`oauth:state:${state}`);
            return {
                profile,
                mode,
                userId
            };
        },
    };
}
//# sourceMappingURL=github.js.map