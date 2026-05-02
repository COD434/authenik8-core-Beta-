"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.createIdentityEngine = createIdentityEngine;
const identityPolicy_1 = require("./identityPolicy");
const auditLogs = [];
function createIdentityEngine(adapter, tokenService) {
    return {
        async resolveOAuth(args) {
            const ctx = {
                email: args.profile.email,
                provider: args.profile.provider,
                providerId: args.profile.providerId,
                mode: args.mode,
                userId: args.userId ?? undefined,
            };
            if (!ctx.email) {
                throw new Error("OAuth profile missing email");
            }
            // 1. Existing provider
            const existingProvider = await adapter.findUserByProvider(ctx.provider, ctx.providerId);
            if (existingProvider) {
                const payload = {
                    userId: existingProvider.id,
                    email: existingProvider.email,
                };
                return {
                    type: "EXISTING_PROVIDER_LOGIN",
                    user: existingProvider,
                    accessToken: await tokenService.signAccessToken(payload),
                    refreshToken: await tokenService.generateRefreshToken(payload),
                };
            }
            // 2. LINK FLOW
            if (ctx.mode === "link") {
                if (!ctx.userId) {
                    return {
                        type: "INVALID_LINK_REQUEST",
                        message: "Missing authenticated user for linking",
                    };
                }
                if (existingProvider && existingProvider.id !== ctx.userId) {
                    throw new Error("Provider already linked to another user");
                }
                await adapter.linkProvider(ctx.userId, ctx.provider, ctx.providerId);
                let user = await adapter.findUserByEmail(ctx.email);
                if (!user) {
                    user = await adapter.findUserByProvider(ctx.provider, ctx.providerId);
                }
                if (!user) {
                    throw new Error("LINK_PROVIDER: user resolution failed");
                }
                auditLogs.push({
                    userId: user.id,
                    action: "PROVIDER_LINKED",
                    timestamp: Date.now(),
                });
                return {
                    type: "LINK_PROVIDER",
                    user,
                    success: true,
                };
            }
            // 3. Check existing by email OR provider (idempotency safety)
            let existingUser = await adapter.findUserByEmail(ctx.email);
            if (existingUser) {
                const isVerified = args.profile.email_verified === true || args.profile.email_verified === "true";
                const canAutoLink = (isVerified && identityPolicy_1.identityPolicy.autoLinkOnVerifiedEmailMatch) || (!isVerified && identityPolicy_1.identityPolicy.allowUnverifiedAutoLink);
                if (!canAutoLink) {
                    return {
                        type: "LINK_REQUIRED",
                        message: "please link manually",
                        email: ctx.email,
                        provider: ctx.provider,
                    };
                }
                const oauthPayload = {
                    userId: existingUser.id,
                    email: existingUser.email,
                };
                return {
                    type: "EXISTING_PROVIDER_LOGIN",
                    user: existingUser,
                    accessToken: await tokenService.signAccessToken(oauthPayload),
                    refreshToken: await tokenService.generateRefreshToken(oauthPayload),
                };
            }
            // 4. Create new user
            const user = await adapter.createUser({
                email: ctx.email,
                provider: ctx.provider,
                providerId: ctx.providerId,
            });
            if (!ctx.providerId) {
                throw new Error("Missing providerId");
            }
            const payload = {
                userId: user.id,
                email: user.email,
            };
            auditLogs.push({
                userId: user.id,
                action: "USER_CREATED",
                timestamp: Date.now(),
            });
            return {
                type: "NEW_USER_CREATION",
                user,
                accessToken: await tokenService.signAccessToken(payload),
                refreshToken: await tokenService.generateRefreshToken(payload)
            };
        },
    };
}
//# sourceMappingURL=identityEngine.js.map