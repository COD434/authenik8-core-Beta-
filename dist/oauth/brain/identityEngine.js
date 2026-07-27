"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.createIdentityEngine = createIdentityEngine;
const crypto_1 = require("crypto");
const identityPolicy_1 = require("./identityPolicy");
const identityValidation_1 = require("../identityValidation");
function createIdentityEngine(adapter, tokenService, audit, policy = identityPolicy_1.identityPolicy) {
    const adapterMethods = [
        "findUserById",
        "findUserByEmail",
        "findUserByProvider",
        "createUser",
        "linkProvider",
    ];
    if (!adapter ||
        adapterMethods.some((method) => typeof adapter[method] !== "function")) {
        throw new Error("OAuth identity adapter is incomplete");
    }
    if (!tokenService || typeof tokenService.issueTokens !== "function") {
        throw new Error("OAuth identity token service is incomplete");
    }
    const resolvedPolicy = (0, identityPolicy_1.resolveIdentityPolicy)(policy);
    const providerBelongsTo = (userValue, ctx) => {
        const user = (0, identityValidation_1.validateIdentityUser)(userValue);
        if (!user.providers.some((entry) => entry.provider === ctx.provider &&
            entry.providerId === ctx.providerId)) {
            throw new Error("OAuth identity adapter provider mismatch");
        }
        return user;
    };
    const emailBelongsTo = (userValue, ctx) => {
        const user = (0, identityValidation_1.validateIdentityUser)(userValue);
        if (user.email !== ctx.email) {
            throw new Error("OAuth identity adapter email mismatch");
        }
        return user;
    };
    const issueExistingLogin = async (user) => ({
        type: "EXISTING_PROVIDER_LOGIN",
        user,
        ...(await issueTokensForUser(user, tokenService)),
    });
    const linkForLogin = async (ctx, user, emailVerified) => {
        if (!canAutoLink(emailVerified, resolvedPolicy)) {
            return {
                type: "LINK_REQUIRED",
                message: "please link manually",
                email: ctx.email,
                provider: ctx.provider,
            };
        }
        await adapter.linkProvider(user.id, ctx.provider, ctx.providerId);
        const linkedUser = providerBelongsTo(await adapter.findUserByProvider(ctx.provider, ctx.providerId), ctx);
        if (linkedUser.id !== user.id) {
            throw new Error("OAuth provider link verification failed");
        }
        await audit?.emit({
            type: "oauth.provider_linked",
            severity: "info",
            outcome: "success",
            actor: { type: "user", id: user.id },
            subject: { type: "user", id: user.id },
            metadata: { provider: ctx.provider, method: "verified_email_policy" },
        });
        return issueExistingLogin(linkedUser);
    };
    return {
        async resolveOAuth(args) {
            if (args.mode !== "login" && args.mode !== "link") {
                throw new Error("OAuth identity mode is invalid");
            }
            if (typeof args.profile.email_verified !== "boolean") {
                throw new Error("OAuth email verification claim is invalid");
            }
            const { provider, providerId } = (0, identityValidation_1.validateIdentityProvider)(args.profile.provider, args.profile.providerId);
            const ctx = {
                email: (0, identityValidation_1.normalizeIdentityEmail)(args.profile.email),
                provider,
                providerId,
                mode: args.mode,
                userId: args.userId === null || args.userId === undefined
                    ? undefined
                    : (0, identityValidation_1.validateIdentityUserId)(args.userId),
            };
            const providerResult = await adapter.findUserByProvider(ctx.provider, ctx.providerId);
            const existingProvider = providerResult
                ? providerBelongsTo(providerResult, ctx)
                : null;
            if (ctx.mode === "link") {
                if (!ctx.userId) {
                    return {
                        type: "INVALID_LINK_REQUEST",
                        message: "Missing authenticated user for linking",
                    };
                }
                const targetResult = await adapter.findUserById(ctx.userId);
                const targetUser = targetResult
                    ? (0, identityValidation_1.validateIdentityUser)(targetResult)
                    : null;
                if (!targetUser || targetUser.id !== ctx.userId) {
                    return {
                        type: "INVALID_LINK_REQUEST",
                        message: "Invalid authenticated user for linking",
                    };
                }
                if (existingProvider && existingProvider.id !== targetUser.id) {
                    await audit?.emit({
                        type: "oauth.provider_link_rejected",
                        severity: "warning",
                        outcome: "denied",
                        actor: { type: "user", id: targetUser.id },
                        subject: { type: "user", id: targetUser.id },
                        metadata: { provider: ctx.provider, reason: "already_linked" },
                    });
                    return {
                        type: "INVALID_LINK_REQUEST",
                        message: "Provider cannot be linked",
                    };
                }
                if (!existingProvider) {
                    await adapter.linkProvider(targetUser.id, ctx.provider, ctx.providerId);
                }
                const linkedResult = await adapter.findUserById(targetUser.id);
                const linkedUser = linkedResult
                    ? (0, identityValidation_1.validateIdentityUser)(linkedResult)
                    : null;
                if (!linkedUser ||
                    !linkedUser.providers.some((entry) => entry.provider === ctx.provider &&
                        entry.providerId === ctx.providerId)) {
                    throw new Error("OAuth provider link verification failed");
                }
                await audit?.emit({
                    type: "oauth.provider_linked",
                    severity: "info",
                    outcome: "success",
                    actor: { type: "user", id: linkedUser.id },
                    subject: { type: "user", id: linkedUser.id },
                    metadata: { provider: ctx.provider, method: "authenticated_link" },
                });
                return {
                    type: "LINK_PROVIDER",
                    user: linkedUser,
                    success: true,
                };
            }
            if (existingProvider) {
                return issueExistingLogin(existingProvider);
            }
            const emailResult = await adapter.findUserByEmail(ctx.email);
            const existingUser = emailResult
                ? emailBelongsTo(emailResult, ctx)
                : null;
            if (existingUser) {
                return linkForLogin(ctx, existingUser, args.profile.email_verified);
            }
            const creation = await adapter.createUser({
                email: ctx.email,
                provider: ctx.provider,
                providerId: ctx.providerId,
            });
            if (!creation ||
                (creation.status !== "created" &&
                    creation.status !== "existing-provider" &&
                    creation.status !== "existing-email")) {
                throw new Error("OAuth identity adapter returned an invalid result");
            }
            if (creation.status === "existing-provider") {
                return issueExistingLogin(providerBelongsTo(creation.user, ctx));
            }
            if (creation.status === "existing-email") {
                return linkForLogin(ctx, emailBelongsTo(creation.user, ctx), args.profile.email_verified);
            }
            const createdUser = providerBelongsTo(emailBelongsTo(creation.user, ctx), ctx);
            await audit?.emit({
                type: "oauth.user_created",
                severity: "info",
                outcome: "success",
                actor: { type: "system" },
                subject: { type: "user", id: createdUser.id },
                metadata: { provider: ctx.provider },
            });
            return {
                type: "NEW_USER_CREATION",
                user: createdUser,
                ...(await issueTokensForUser(createdUser, tokenService)),
            };
        },
    };
}
const canAutoLink = (emailVerified, policy) => {
    return ((emailVerified === true && policy.autoLinkOnVerifiedEmailMatch) ||
        (emailVerified === false && policy.allowUnverifiedAutoLink));
};
const issueTokensForUser = async (user, tokenService) => tokenService.issueTokens({
    userId: user.id,
    email: user.email,
    sessionId: (0, crypto_1.randomUUID)(),
    ...(typeof user.role === "string" ? { role: user.role.toLowerCase() } : {}),
});
//# sourceMappingURL=identityEngine.js.map