"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.findUserByEmail = findUserByEmail;
exports.findUserByProvider = findUserByProvider;
exports.createUser = createUser;
exports.linkProvider = linkProvider;
const crypto_1 = __importDefault(require("crypto"));
const users = [];
async function findUserByEmail(email) {
    return users.find((u) => u.email === email);
}
async function findUserByProvider(provider, providerId) {
    return users.find((u) => u.providers.some((p) => p.provider === provider && p.providerId === providerId));
}
async function createUser(data) {
    const newUser = {
        id: crypto_1.default.randomUUID(),
        email: data.email,
        providers: [
            {
                provider: data.provider,
                providerId: data.providerId,
            },
        ],
    };
    users.push(newUser);
    return newUser;
}
async function linkProvider(userId, provider, providerId) {
    const user = users.find((u) => u.id === userId);
    if (!user)
        return;
    const alreadyLinked = user.providers.some((p) => p.provider === provider);
    if (!alreadyLinked) {
        user.providers.push({ provider, providerId });
    }
}
//# sourceMappingURL=userStore.js.map