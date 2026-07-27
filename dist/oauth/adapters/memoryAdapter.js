"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.memoryAdapter = void 0;
const crypto_1 = require("crypto");
const identityValidation_1 = require("../identityValidation");
const users = new Map();
const copyUser = (user) => structuredClone(user);
exports.memoryAdapter = {
    async findUserById(userId) {
        const user = users.get((0, identityValidation_1.validateIdentityUserId)(userId));
        return user ? copyUser(user) : null;
    },
    async findUserByEmail(email) {
        const normalizedEmail = (0, identityValidation_1.normalizeIdentityEmail)(email);
        const user = [...users.values()].find((candidate) => candidate.email === normalizedEmail);
        return user ? copyUser(user) : null;
    },
    async findUserByProvider(provider, providerId) {
        const identity = (0, identityValidation_1.validateIdentityProvider)(provider, providerId);
        const user = [...users.values()].find((candidate) => candidate.providers.some((entry) => entry.provider === identity.provider &&
            entry.providerId === identity.providerId));
        return user ? copyUser(user) : null;
    },
    async createUser(data) {
        const normalizedEmail = (0, identityValidation_1.normalizeIdentityEmail)(data.email);
        const identity = (0, identityValidation_1.validateIdentityProvider)(data.provider, data.providerId);
        const existingProvider = await this.findUserByProvider(identity.provider, identity.providerId);
        if (existingProvider) {
            return { status: "existing-provider", user: existingProvider };
        }
        const existingEmail = await this.findUserByEmail(normalizedEmail);
        if (existingEmail) {
            return { status: "existing-email", user: existingEmail };
        }
        const user = {
            id: (0, crypto_1.randomUUID)(),
            email: normalizedEmail,
            providers: [
                identity,
            ],
        };
        users.set(user.id, copyUser(user));
        return { status: "created", user: copyUser(user) };
    },
    async linkProvider(userId, provider, providerId) {
        const validUserId = (0, identityValidation_1.validateIdentityUserId)(userId);
        const identity = (0, identityValidation_1.validateIdentityProvider)(provider, providerId);
        const providerOwner = await this.findUserByProvider(identity.provider, identity.providerId);
        if (providerOwner && providerOwner.id !== validUserId) {
            throw new Error("OAuth provider is already linked");
        }
        const user = users.get(validUserId);
        if (!user) {
            throw new Error("OAuth link target user not found");
        }
        if (!user.providers.some((entry) => entry.provider === identity.provider &&
            entry.providerId === identity.providerId)) {
            if (user.providers.length >= identityValidation_1.MAX_IDENTITY_PROVIDERS_PER_USER) {
                throw new Error("OAuth identity provider limit exceeded");
            }
            users.set(validUserId, {
                ...user,
                providers: [...user.providers, identity],
            });
        }
    },
    reset() {
        users.clear();
    },
    dump() {
        return [...users.values()].map(copyUser);
    },
};
//# sourceMappingURL=memoryAdapter.js.map