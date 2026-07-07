"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Store = exports.hashPassword = void 0;
const crypto_1 = require("crypto");
const util_1 = require("util");
const scrypt = (0, util_1.promisify)(crypto_1.scrypt);
const PASSWORD_KEY_LENGTH = 64;
const hashPassword = async (password) => {
    const salt = (0, crypto_1.randomBytes)(16).toString("hex");
    const derivedKey = (await scrypt(password, salt, PASSWORD_KEY_LENGTH));
    return `scrypt$${salt}$${derivedKey.toString("hex")}`;
};
exports.hashPassword = hashPassword;
class Store {
    constructor(userStore) {
        this.userStore = userStore;
    }
    async register(email, password) {
        const exists = await this.userStore.findByEmail(email);
        if (exists) {
            throw new Error("If a record of user exists an email will be sent");
        }
        const passwordHash = await (0, exports.hashPassword)(password);
        await this.userStore.create({ email, passwordHash });
    }
}
exports.Store = Store;
//# sourceMappingURL=userStorage.js.map