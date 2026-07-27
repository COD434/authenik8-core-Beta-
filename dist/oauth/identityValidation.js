"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.validateIdentityUser = exports.validateIdentityUserId = exports.validateIdentityProvider = exports.normalizeIdentityEmail = exports.MAX_IDENTITY_ROLE_LENGTH = exports.MAX_IDENTITY_PROVIDERS_PER_USER = exports.MAX_IDENTITY_PROVIDER_ID_LENGTH = exports.MAX_IDENTITY_USER_ID_LENGTH = exports.MAX_IDENTITY_EMAIL_LENGTH = void 0;
const safeString_1 = require("../utility/safeString");
exports.MAX_IDENTITY_EMAIL_LENGTH = 254;
exports.MAX_IDENTITY_USER_ID_LENGTH = 256;
exports.MAX_IDENTITY_PROVIDER_ID_LENGTH = 512;
exports.MAX_IDENTITY_PROVIDERS_PER_USER = 32;
exports.MAX_IDENTITY_ROLE_LENGTH = 128;
const PROVIDER_PATTERN = /^[a-z][a-z0-9._-]{0,63}$/;
const normalizeIdentityEmail = (value) => {
    if (typeof value !== "string") {
        throw new Error("OAuth profile has an invalid email");
    }
    const email = value.trim().toLowerCase();
    const at = email.indexOf("@");
    if (email.length === 0 ||
        email.length > exports.MAX_IDENTITY_EMAIL_LENGTH ||
        (0, safeString_1.containsControlCharacter)(email) ||
        at <= 0 ||
        at !== email.lastIndexOf("@") ||
        at === email.length - 1) {
        throw new Error("OAuth profile has an invalid email");
    }
    return email;
};
exports.normalizeIdentityEmail = normalizeIdentityEmail;
const validateIdentityProvider = (providerValue, providerIdValue) => {
    if (typeof providerValue !== "string" ||
        !PROVIDER_PATTERN.test(providerValue)) {
        throw new Error("OAuth identity provider is invalid");
    }
    if (typeof providerIdValue !== "string" ||
        providerIdValue.length === 0 ||
        providerIdValue.length > exports.MAX_IDENTITY_PROVIDER_ID_LENGTH ||
        (0, safeString_1.containsControlCharacter)(providerIdValue)) {
        throw new Error("OAuth providerId is invalid");
    }
    return { provider: providerValue, providerId: providerIdValue };
};
exports.validateIdentityProvider = validateIdentityProvider;
const validateIdentityUserId = (value) => {
    if (typeof value !== "string" ||
        value.length === 0 ||
        value.length > exports.MAX_IDENTITY_USER_ID_LENGTH ||
        (0, safeString_1.containsControlCharacter)(value)) {
        throw new Error("OAuth identity user is invalid");
    }
    return value;
};
exports.validateIdentityUserId = validateIdentityUserId;
const validateIdentityUser = (value) => {
    if (!value || typeof value !== "object") {
        throw new Error("OAuth identity adapter returned an invalid user");
    }
    const candidate = value;
    const id = (0, exports.validateIdentityUserId)(candidate.id);
    const email = (0, exports.normalizeIdentityEmail)(candidate.email);
    if (email !== candidate.email) {
        throw new Error("OAuth identity user email must be normalized");
    }
    if (candidate.role !== undefined &&
        (typeof candidate.role !== "string" ||
            candidate.role.length === 0 ||
            candidate.role.length > exports.MAX_IDENTITY_ROLE_LENGTH ||
            (0, safeString_1.containsControlCharacter)(candidate.role))) {
        throw new Error("OAuth identity user role is invalid");
    }
    if (!Array.isArray(candidate.providers) ||
        candidate.providers.length > exports.MAX_IDENTITY_PROVIDERS_PER_USER) {
        throw new Error("OAuth identity user providers are invalid");
    }
    const providers = candidate.providers.map((entry) => {
        if (!entry || typeof entry !== "object") {
            throw new Error("OAuth identity user provider is invalid");
        }
        return (0, exports.validateIdentityProvider)(entry.provider, entry.providerId);
    });
    if (new Set(providers.map((entry) => `${entry.provider}\0${entry.providerId}`)).size !== providers.length) {
        throw new Error("OAuth identity user contains duplicate providers");
    }
    return {
        id,
        email,
        ...(candidate.role !== undefined ? { role: candidate.role } : {}),
        providers,
    };
};
exports.validateIdentityUser = validateIdentityUser;
//# sourceMappingURL=identityValidation.js.map