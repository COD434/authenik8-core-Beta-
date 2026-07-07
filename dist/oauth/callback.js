"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.finalizeOAuthCallback = void 0;
const finalizeOAuthCallback = async (profile, mode, userId, identityEngine) => {
    if (!identityEngine) {
        return { profile, mode, userId };
    }
    const identity = await identityEngine.resolveOAuth({ profile, mode, userId });
    if (!identity) {
        return { profile, mode, userId };
    }
    const result = { profile, mode, userId, identity };
    if (identity.type === "EXISTING_PROVIDER_LOGIN" ||
        identity.type === "NEW_USER_CREATION") {
        result.accessToken = identity.accessToken;
        result.refreshToken = identity.refreshToken;
    }
    return result;
};
exports.finalizeOAuthCallback = finalizeOAuthCallback;
//# sourceMappingURL=callback.js.map