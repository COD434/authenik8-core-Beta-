"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.resolveIdentity = resolveIdentity;
const userStore_1 = require("../userStore");
const identityPolicy_1 = require("./identityPolicy");
async function resolveIdentity(profile) {
    const { email, provider, providerId } = profile;
    const byProvider = await (0, userStore_1.findUserByProvider)(provider, providerId);
    if (byProvider) {
        return byProvider;
    }
    const existingUser = await (0, userStore_1.findUserByEmail)(email);
    if (!existingUser) {
        return (0, userStore_1.createUser)({
            email,
            provider,
            providerId,
        });
    }
    const isVerifiedEmail = true;
    if (identityPolicy_1.identityPolicy.autoLinkOnVerifiedEmailMatch &&
        isVerifiedEmail) {
        await (0, userStore_1.linkProvider)(existingUser.id, provider, providerId);
        return existingUser;
    }
    return {
        type: "IDENTITY_CONFLICT",
        user: existingUser,
        message: "Account exists. Explicit linking required.",
    };
}
//# sourceMappingURL=identityResolver.js.map