"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.redisKey = exports.resolveRedisKeyPrefix = exports.validateRedisKeyPrefix = void 0;
const crypto_1 = require("crypto");
const MAX_PREFIX_LENGTH = 128;
const PREFIX_PATTERN = /^[A-Za-z0-9][A-Za-z0-9:._-]*$/;
const validateRedisKeyPrefix = (prefix) => {
    const normalized = prefix.trim();
    if (!normalized ||
        normalized.length > MAX_PREFIX_LENGTH ||
        !PREFIX_PATTERN.test(normalized) ||
        normalized.endsWith(":")) {
        throw new Error("redisKeyPrefix must be 1-128 letters, numbers, colons, dots, underscores, or hyphens and may not end with a colon");
    }
    return normalized;
};
exports.validateRedisKeyPrefix = validateRedisKeyPrefix;
const resolveRedisKeyPrefix = (configuredPrefix, issuer, audience) => {
    if (configuredPrefix !== undefined) {
        return (0, exports.validateRedisKeyPrefix)(configuredPrefix);
    }
    const audiences = Array.isArray(audience) ? audience : [audience];
    const securityDomain = (0, crypto_1.createHash)("sha256")
        .update(issuer)
        .update("\0")
        .update(audiences.join("\0"))
        .digest("base64url")
        .slice(0, 22);
    return `authenik8:v2:${securityDomain}`;
};
exports.resolveRedisKeyPrefix = resolveRedisKeyPrefix;
const redisKey = (prefix, ...parts) => [prefix, ...parts].join(":");
exports.redisKey = redisKey;
//# sourceMappingURL=keyNamespace.js.map