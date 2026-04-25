"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.memoryAdapter = void 0;
const crypto_1 = require("crypto");
// 🔥 SINGLE SOURCE OF TRUTH (REAL MEMORY STORE)
const users = new Map();
exports.memoryAdapter = {
    async findUserByEmail(email) {
        return [...users.values()].find((u) => u.email === email) || null;
    },
    async findUserByProvider(provider, providerId) {
        return ([...users.values()].find((u) => u.providers.some((p) => p.provider === provider && p.providerId === providerId)) || null);
    },
    async createUser(data) {
        const user = {
            id: (0, crypto_1.randomUUID)(),
            email: data.email,
            providers: [
                {
                    provider: data.provider,
                    providerId: data.providerId,
                },
            ],
        };
        users.set(user.id, user);
        return user;
    },
    async linkProvider(userId, provider, providerId) {
        const user = users.get(userId);
        if (!user) {
            throw new Error(`User not found: ${userId}`);
        }
        user.providers.push({ provider, providerId });
        users.set(userId, user);
    },
    reset() {
        users.clear();
    },
    dump() {
        return [...users.values()];
    },
};
//# sourceMappingURL=memoryAdapter.js.map