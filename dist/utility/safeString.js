"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.containsControlCharacter = void 0;
const containsControlCharacter = (value) => {
    for (let index = 0; index < value.length; index += 1) {
        const code = value.charCodeAt(index);
        if (code <= 0x1f || code === 0x7f)
            return true;
    }
    return false;
};
exports.containsControlCharacter = containsControlCharacter;
//# sourceMappingURL=safeString.js.map