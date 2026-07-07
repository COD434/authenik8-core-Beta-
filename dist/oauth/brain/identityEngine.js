"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.createIdentityEngine = createIdentityEngine;
const identityPolicy_1 = require("./identityPolicy");
const crypto_1 = require("crypto");
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
            if (!ctx.providerId) {
                throw new Error("Missing providerId");
            }
            const existingProvider = await adapter.findUserByProvider(ctx.provider, ctx.providerId);
            if (existingProvider) {
                return {
                    type: "EXISTING_PROVIDER_LOGIN",
                    user: existingProvider,
                    ...(await issueTokensForUser(existingProvider, tokenService)),
                };
            }
            if (ctx.mode === "link") {
                if (!ctx.userId) {
                    return {
                        type: "INVALID_LINK_REQUEST",
                        message: "Missing authenticated user for linking",
                    };
                }
                await adapter.linkProvider(ctx.userId, ctx.provider, ctx.providerId);
                const user = (await adapter.findUserByEmail(ctx.email)) ??
                    (await adapter.findUserByProvider(ctx.provider, ctx.providerId));
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
            const existingUser = await adapter.findUserByEmail(ctx.email);
            if (existingUser) {
                if (!canAutoLink(args.profile.email_verified)) {
                    return {
                        type: "LINK_REQUIRED",
                        message: "please link manually",
                        email: ctx.email,
                        provider: ctx.provider,
                    };
                }
                return {
                    type: "EXISTING_PROVIDER_LOGIN",
                    user: existingUser,
                    ...(await issueTokensForUser(existingUser, tokenService)),
                };
            }
            const user = await adapter.createUser({
                email: ctx.email,
                provider: ctx.provider,
                providerId: ctx.providerId,
            });
            auditLogs.push({
                userId: user.id,
                action: "USER_CREATED",
                timestamp: Date.now(),
            });
            return {
                type: "NEW_USER_CREATION",
                user,
                ...(await issueTokensForUser(user, tokenService)),
            };
        },
    };
}
const canAutoLink = (emailVerified) => {
    const isVerified = emailVerified === true || emailVerified === "true";
    return ((isVerified && identityPolicy_1.identityPolicy.autoLinkOnVerifiedEmailMatch) ||
        (!isVerified && identityPolicy_1.identityPolicy.allowUnverifiedAutoLink));
};
const issueTokensForUser = async (user, tokenService) => {
    const payload = {
        userId: user.id,
        email: user.email,
        sessionId: (0, crypto_1.randomUUID)(),
    };
    return {
        accessToken: await tokenService.signAccessToken(payload),
        refreshToken: await tokenService.generateRefreshToken(payload),
    };
};
//# sourceMappingURL=identityEngine.js.map