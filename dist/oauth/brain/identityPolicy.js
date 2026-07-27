"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.resolveIdentityPolicy = exports.identityPolicy = void 0;
exports.identityPolicy = Object.freeze({
    autoLinkOnVerifiedEmailMatch: false,
    allowUnverifiedAutoLink: false,
});
const resolveIdentityPolicy = (configured = {}) => {
    if ((configured.autoLinkOnVerifiedEmailMatch !== undefined &&
        typeof configured.autoLinkOnVerifiedEmailMatch !== "boolean") ||
        (configured.allowUnverifiedAutoLink !== undefined &&
            typeof configured.allowUnverifiedAutoLink !== "boolean")) {
        throw new Error("OAuth identity policy flags must be boolean values");
    }
    return Object.freeze({
        autoLinkOnVerifiedEmailMatch: configured.autoLinkOnVerifiedEmailMatch ?? false,
        allowUnverifiedAutoLink: configured.allowUnverifiedAutoLink ?? false,
    });
};
exports.resolveIdentityPolicy = resolveIdentityPolicy;
//# sourceMappingURL=identityPolicy.js.map