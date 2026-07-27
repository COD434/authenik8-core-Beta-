"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.authenticatedUserId = exports.readOAuthQueryValue = exports.validateOAuthProviderConfig = exports.readBoundedJsonResponse = exports.MAX_OAUTH_JSON_RESPONSE_BYTES = exports.MAX_OAUTH_CODE_LENGTH = exports.OAUTH_HTTP_TIMEOUT_MS = void 0;
const safeString_1 = require("../utility/safeString");
exports.OAUTH_HTTP_TIMEOUT_MS = 10000;
exports.MAX_OAUTH_CODE_LENGTH = 4096;
exports.MAX_OAUTH_JSON_RESPONSE_BYTES = 64 * 1024;
const readBoundedJsonResponse = async (response, maximumBytes = exports.MAX_OAUTH_JSON_RESPONSE_BYTES) => {
    if (!Number.isSafeInteger(maximumBytes) || maximumBytes < 1) {
        throw new Error("OAuth response size limit is invalid");
    }
    // A stream is required so the decompressed body can be bounded before parse.
    if (!response.body || typeof response.body.getReader !== "function") {
        throw new Error("OAuth provider response body is unavailable");
    }
    const declaredLength = Number(response.headers?.get("content-length"));
    if (Number.isFinite(declaredLength) && declaredLength > maximumBytes) {
        await response.body.cancel();
        throw new Error("OAuth provider response exceeds the size limit");
    }
    const reader = response.body.getReader();
    const chunks = [];
    let size = 0;
    try {
        while (true) {
            const { done, value } = await reader.read();
            if (done)
                break;
            size += value.byteLength;
            if (size > maximumBytes) {
                await reader.cancel();
                throw new Error("OAuth provider response exceeds the size limit");
            }
            chunks.push(value);
        }
    }
    finally {
        reader.releaseLock();
    }
    try {
        return JSON.parse(Buffer.concat(chunks, size).toString("utf8"));
    }
    catch {
        throw new Error("OAuth provider returned invalid JSON");
    }
};
exports.readBoundedJsonResponse = readBoundedJsonResponse;
const validateOAuthProviderConfig = (config) => {
    if (typeof config.clientId !== "string" ||
        config.clientId.length === 0 ||
        config.clientId.length > 512) {
        throw new Error("OAuth clientId must contain between 1 and 512 characters");
    }
    if (typeof config.clientSecret !== "string" ||
        Buffer.byteLength(config.clientSecret, "utf8") < 16 ||
        Buffer.byteLength(config.clientSecret, "utf8") > 4096) {
        throw new Error("OAuth clientSecret must contain between 16 and 4096 bytes");
    }
    let redirect;
    try {
        redirect = new URL(config.redirectUri);
    }
    catch {
        throw new Error("OAuth redirectUri must be an absolute URL");
    }
    const loopback = redirect.hostname === "localhost" ||
        redirect.hostname === "127.0.0.1" ||
        redirect.hostname === "[::1]";
    if ((redirect.protocol !== "https:" &&
        !(redirect.protocol === "http:" && loopback)) ||
        redirect.username ||
        redirect.password ||
        redirect.hash) {
        throw new Error("OAuth redirectUri must use HTTPS (HTTP is allowed only for loopback development)");
    }
};
exports.validateOAuthProviderConfig = validateOAuthProviderConfig;
const readOAuthQueryValue = (request, name) => {
    const value = request.query[name];
    if (typeof value !== "string" ||
        value.length === 0 ||
        value.length > exports.MAX_OAUTH_CODE_LENGTH ||
        (0, safeString_1.containsControlCharacter)(value)) {
        return null;
    }
    return value;
};
exports.readOAuthQueryValue = readOAuthQueryValue;
const authenticatedUserId = (request) => {
    const userId = request.user
        ?.userId;
    return typeof userId === "string" &&
        userId.length > 0 &&
        userId.length <= 256 &&
        !(0, safeString_1.containsControlCharacter)(userId)
        ? userId
        : null;
};
exports.authenticatedUserId = authenticatedUserId;
//# sourceMappingURL=providerSecurity.js.map