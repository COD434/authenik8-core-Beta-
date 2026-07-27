"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.tokenFingerprintMatches = exports.tokenFingerprint = void 0;
const crypto_1 = require("crypto");
const tokenFingerprint = (token) => (0, crypto_1.createHash)("sha256").update(token).digest("base64url");
exports.tokenFingerprint = tokenFingerprint;
const tokenFingerprintMatches = (expectedFingerprint, token) => {
    const expected = Buffer.from(expectedFingerprint);
    const actual = Buffer.from((0, exports.tokenFingerprint)(token));
    return (expected.length === actual.length && (0, crypto_1.timingSafeEqual)(expected, actual));
};
exports.tokenFingerprintMatches = tokenFingerprintMatches;
//# sourceMappingURL=tokenFingerprint.js.map