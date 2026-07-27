"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.consumeOAuthState = exports.parseOAuthState = exports.isValidOAuthState = exports.isValidOAuthStateToken = exports.MAX_OAUTH_STATE_RECORD_BYTES = exports.OAUTH_STATE_TTL_SECONDS = exports.OAUTH_STATE_BYTES = void 0;
const safeString_1 = require("../utility/safeString");
exports.OAUTH_STATE_BYTES = 32;
exports.OAUTH_STATE_TTL_SECONDS = 300;
exports.MAX_OAUTH_STATE_RECORD_BYTES = 1024;
const OAUTH_STATE_PATTERN = /^[a-f0-9]{64}$/;
const isValidOAuthStateToken = (state) => typeof state === "string" && OAUTH_STATE_PATTERN.test(state);
exports.isValidOAuthStateToken = isValidOAuthStateToken;
const isValidOAuthState = (value) => {
    if (!value || typeof value !== "object")
        return false;
    try {
        const candidate = value;
        const keys = Object.keys(candidate).sort();
        if (keys.length !== 2 ||
            keys[0] !== "mode" ||
            keys[1] !== "userId") {
            return false;
        }
        return ((candidate.mode === "login" && candidate.userId === null) ||
            (candidate.mode === "link" &&
                typeof candidate.userId === "string" &&
                candidate.userId.length > 0 &&
                candidate.userId.length <= 256 &&
                !(0, safeString_1.containsControlCharacter)(candidate.userId)));
    }
    catch {
        return false;
    }
};
exports.isValidOAuthState = isValidOAuthState;
const parseOAuthState = (serialized) => {
    if (typeof serialized !== "string" ||
        Buffer.byteLength(serialized, "utf8") > exports.MAX_OAUTH_STATE_RECORD_BYTES) {
        return null;
    }
    try {
        const value = JSON.parse(serialized);
        return (0, exports.isValidOAuthState)(value) ? value : null;
    }
    catch {
        return null;
    }
};
exports.parseOAuthState = parseOAuthState;
const consumeOAuthState = async (store, state) => {
    if (!(0, exports.isValidOAuthStateToken)(state))
        return null;
    const value = await store.take(state);
    return (0, exports.isValidOAuthState)(value) ? value : null;
};
exports.consumeOAuthState = consumeOAuthState;
//# sourceMappingURL=state.js.map