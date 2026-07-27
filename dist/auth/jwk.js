"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.verifyAccessTokenWithJwks = exports.generateSigningJwk = exports.decodeBoundedJwt = exports.JwtKeyRing = exports.normalizeTokenLifetime = exports.MINIMUM_HMAC_SECRET_BYTES = exports.DEFAULT_TOKEN_AUDIENCE = exports.DEFAULT_TOKEN_ISSUER = exports.LEGACY_TOKEN_ALGORITHM = exports.ACCESS_TOKEN_ALGORITHM = exports.loadJose = void 0;
const crypto_1 = require("crypto");
const safeString_1 = require("../utility/safeString");
const loadJose = () => import("jose");
exports.loadJose = loadJose;
exports.ACCESS_TOKEN_ALGORITHM = "ES256";
exports.LEGACY_TOKEN_ALGORITHM = "HS256";
exports.DEFAULT_TOKEN_ISSUER = "authenik8-core";
exports.DEFAULT_TOKEN_AUDIENCE = "authenik8-api";
exports.MINIMUM_HMAC_SECRET_BYTES = 32;
const MAX_COMPACT_JWT_LENGTH = 16 * 1024;
const MAX_JWK_KEYS = 16;
const MAX_ISSUER_LENGTH = 2048;
const MAX_AUDIENCES = 32;
const MAX_AUDIENCE_LENGTH = 512;
const MAX_KID_LENGTH = 128;
const MAX_GENERIC_TOKEN_TTL_SECONDS = 31 * 24 * 60 * 60;
const assertCanonicalCompactJwt = (token) => {
    if (!token || token.length > MAX_COMPACT_JWT_LENGTH) {
        throw new Error(`JWT must be between 1 and ${MAX_COMPACT_JWT_LENGTH} characters`);
    }
    const segments = token.split(".");
    if (segments.length !== 3 || segments.some((segment) => !segment)) {
        throw new Error("JWT must contain three non-empty compact segments");
    }
    for (const segment of segments) {
        const decoded = Buffer.from(segment, "base64url");
        if (decoded.toString("base64url") !== segment) {
            throw new Error("JWT contains non-canonical base64url encoding");
        }
    }
};
const hmacSecret = (secret, label) => {
    const encoded = new TextEncoder().encode(secret);
    if (encoded.length < exports.MINIMUM_HMAC_SECRET_BYTES ||
        encoded.length > 4096) {
        throw new Error(`${label} must contain between ${exports.MINIMUM_HMAC_SECRET_BYTES} and 4096 bytes of cryptographically random material`);
    }
    return encoded;
};
const normalizeTokenLifetime = (value, label, minimumSeconds, maximumSeconds) => {
    let seconds;
    if (typeof value === "number") {
        seconds = value;
    }
    else {
        const match = /^(\d+)([smhd])$/.exec(value);
        if (!match) {
            throw new Error(`${label} must use a whole-number s, m, h, or d duration`);
        }
        const amount = Number(match[1]);
        const multiplier = match[2] === "s"
            ? 1
            : match[2] === "m"
                ? 60
                : match[2] === "h"
                    ? 3600
                    : 86400;
        seconds = amount * multiplier;
    }
    if (!Number.isSafeInteger(seconds) ||
        seconds < minimumSeconds ||
        seconds > maximumSeconds) {
        throw new Error(`${label} must be between ${minimumSeconds} and ${maximumSeconds} seconds`);
    }
    return seconds;
};
exports.normalizeTokenLifetime = normalizeTokenLifetime;
const assertBoundedClaim = (value, label, maximumLength) => {
    if (typeof value !== "string" ||
        value.length === 0 ||
        value.length > maximumLength ||
        (0, safeString_1.containsControlCharacter)(value)) {
        throw new Error(`${label} is invalid or exceeds ${maximumLength} characters`);
    }
};
const validateIssuerAndAudience = (issuer, audience, prefix) => {
    assertBoundedClaim(issuer, `${prefix}.issuer`, MAX_ISSUER_LENGTH);
    const audiences = Array.isArray(audience) ? audience : [audience];
    if (audiences.length === 0 ||
        audiences.length > MAX_AUDIENCES) {
        throw new Error(`${prefix}.audience must contain between 1 and ${MAX_AUDIENCES} values`);
    }
    audiences.forEach((entry) => assertBoundedClaim(entry, `${prefix}.audience`, MAX_AUDIENCE_LENGTH));
};
const assertP256Component = (value, label, kid) => {
    if (typeof value !== "string") {
        throw new Error(`JWT key ${kid} must include ${label}`);
    }
    const decoded = Buffer.from(value, "base64url");
    if (decoded.length !== 32 ||
        decoded.toString("base64url") !== value) {
        throw new Error(`JWT key ${kid} has an invalid P-256 ${label} value`);
    }
};
const publicJwk = (key) => {
    return {
        kty: key.kty,
        crv: key.crv,
        x: key.x,
        y: key.y,
        kid: key.kid,
        alg: exports.ACCESS_TOKEN_ALGORITHM,
        use: "sig",
        key_ops: ["verify"],
    };
};
const validateJwkConfig = (config) => {
    validateIssuerAndAudience(config.issuer, config.audience, "jwt");
    assertBoundedClaim(config.activeKid, "jwt.activeKid", MAX_KID_LENGTH);
    if (!config.keys.length || config.keys.length > MAX_JWK_KEYS) {
        throw new Error(`jwt.keys must contain between 1 and ${MAX_JWK_KEYS} keys`);
    }
    const kids = new Set();
    for (const key of config.keys) {
        if (!key.kid)
            throw new Error("Every JWT signing key must have a kid");
        assertBoundedClaim(key.kid, "JWT kid", MAX_KID_LENGTH);
        if (kids.has(key.kid))
            throw new Error(`Duplicate JWT kid: ${key.kid}`);
        kids.add(key.kid);
        if (key.kty !== "EC" || key.crv !== "P-256") {
            throw new Error(`JWT key ${key.kid} must be an ES256 P-256 EC JWK`);
        }
        assertP256Component(key.x, "x coordinate", key.kid);
        assertP256Component(key.y, "y coordinate", key.kid);
        if (key.d !== undefined) {
            assertP256Component(key.d, "private scalar", key.kid);
        }
        if (key.alg && key.alg !== exports.ACCESS_TOKEN_ALGORITHM) {
            throw new Error(`JWT key ${key.kid} must use ${exports.ACCESS_TOKEN_ALGORITHM}`);
        }
        if (key.use && key.use !== "sig") {
            throw new Error(`JWT key ${key.kid} must declare use=sig`);
        }
        if (key.key_ops &&
            !key.key_ops.includes(key.d ? "sign" : "verify")) {
            throw new Error(`JWT key ${key.kid} has incompatible key_ops`);
        }
    }
    const activeKey = config.keys.find((key) => key.kid === config.activeKid);
    if (!activeKey)
        throw new Error(`Active JWT kid not found: ${config.activeKid}`);
    if (!activeKey.d)
        throw new Error(`Active JWT key ${config.activeKid} must be private`);
};
const cloneJwkConfig = (config) => ({
    ...config,
    audience: Array.isArray(config.audience)
        ? [...config.audience]
        : config.audience,
    keys: config.keys.map((key) => ({
        ...key,
        ...(key.key_ops ? { key_ops: [...key.key_ops] } : {}),
    })),
});
class JwtKeyRing {
    constructor(options) {
        if (options.jwk) {
            const jwk = cloneJwkConfig(options.jwk);
            validateJwkConfig(jwk);
            this.jwk = jwk;
            this.issuer = jwk.issuer;
            this.audience = jwk.audience;
            return;
        }
        if (!options.legacySecret) {
            throw new Error("Configure jwt.keys or provide the deprecated jwtSecret");
        }
        this.legacySecret = hmacSecret(options.legacySecret, "JWT HMAC secret");
        this.issuer = options.issuer ?? exports.DEFAULT_TOKEN_ISSUER;
        this.audience = options.audience ?? exports.DEFAULT_TOKEN_AUDIENCE;
        validateIssuerAndAudience(this.issuer, this.audience, "jwt");
    }
    async sign(payload, options) {
        if (!Number.isSafeInteger(options.expiresInSeconds) ||
            options.expiresInSeconds < 1 ||
            options.expiresInSeconds > MAX_GENERIC_TOKEN_TTL_SECONDS) {
            throw new Error(`JWT expiry must be between 1 and ${MAX_GENERIC_TOKEN_TTL_SECONDS} seconds`);
        }
        const { SignJWT } = await (0, exports.loadJose)();
        const now = Math.floor(Date.now() / 1000);
        const jwt = new SignJWT({ ...payload, tokenUse: options.tokenUse })
            .setProtectedHeader(this.protectedHeader())
            .setIssuer(this.issuer)
            .setAudience(this.audience)
            .setIssuedAt(now)
            .setJti((0, crypto_1.randomUUID)())
            .setExpirationTime(now + options.expiresInSeconds);
        if (this.jwk) {
            return jwt.sign(this.activePrivateJwk());
        }
        return jwt.sign(this.legacySecret);
    }
    async verify(token, tokenUse) {
        assertCanonicalCompactJwt(token);
        const { createLocalJWKSet, jwtVerify } = await (0, exports.loadJose)();
        const { payload } = this.jwk
            ? await jwtVerify(token, createLocalJWKSet(this.getJwks()), {
                algorithms: [exports.ACCESS_TOKEN_ALGORITHM],
                issuer: this.issuer,
                audience: this.audience,
            })
            : await jwtVerify(token, this.legacySecret, {
                algorithms: [exports.LEGACY_TOKEN_ALGORITHM],
                issuer: this.issuer,
                audience: this.audience,
            });
        if (payload.tokenUse !== tokenUse) {
            throw new Error(`Expected a ${tokenUse} token`);
        }
        return payload;
    }
    getJwks() {
        return {
            keys: this.jwk?.keys.map(publicJwk) ?? [],
        };
    }
    activePrivateJwk() {
        return this.jwk.keys.find((key) => key.kid === this.jwk.activeKid);
    }
    protectedHeader() {
        return this.jwk
            ? { alg: exports.ACCESS_TOKEN_ALGORITHM, kid: this.jwk.activeKid, typ: "JWT" }
            : { alg: exports.LEGACY_TOKEN_ALGORITHM, kid: "legacy-hs256", typ: "JWT" };
    }
}
exports.JwtKeyRing = JwtKeyRing;
const decodeBoundedJwt = async (token) => {
    assertCanonicalCompactJwt(token);
    const { decodeJwt } = await (0, exports.loadJose)();
    return decodeJwt(token);
};
exports.decodeBoundedJwt = decodeBoundedJwt;
const generateSigningJwk = async (kid) => {
    const { calculateJwkThumbprint, exportJWK, generateKeyPair } = await (0, exports.loadJose)();
    const { privateKey, publicKey } = await generateKeyPair(exports.ACCESS_TOKEN_ALGORITHM, {
        extractable: true,
    });
    const [privateKeyJwk, publicKeyJwk] = await Promise.all([
        exportJWK(privateKey),
        exportJWK(publicKey),
    ]);
    const resolvedKid = kid ?? (await calculateJwkThumbprint(publicKeyJwk));
    assertBoundedClaim(resolvedKid, "JWT kid", MAX_KID_LENGTH);
    return {
        ...privateKeyJwk,
        alg: exports.ACCESS_TOKEN_ALGORITHM,
        use: "sig",
        key_ops: ["sign"],
        kid: resolvedKid,
    };
};
exports.generateSigningJwk = generateSigningJwk;
const verifyAccessTokenWithJwks = async (token, jwks, options) => {
    assertCanonicalCompactJwt(token);
    validateIssuerAndAudience(options.issuer, options.audience, "verification");
    const { createLocalJWKSet, createRemoteJWKSet, jwtVerify } = await (0, exports.loadJose)();
    let resolver;
    if (jwks instanceof URL) {
        if (jwks.protocol !== "https:" ||
            jwks.username ||
            jwks.password ||
            jwks.hash) {
            throw new Error("Remote JWKS URLs must use credential-free HTTPS");
        }
        resolver = createRemoteJWKSet(jwks);
    }
    else {
        validatePublicJwks(jwks);
        resolver = createLocalJWKSet(jwks);
    }
    const { payload } = await jwtVerify(token, resolver, {
        algorithms: [exports.ACCESS_TOKEN_ALGORITHM],
        issuer: options.issuer,
        audience: options.audience,
    });
    if (payload.tokenUse !== "access") {
        throw new Error("Expected an access token");
    }
    return payload;
};
exports.verifyAccessTokenWithJwks = verifyAccessTokenWithJwks;
const validatePublicJwks = (jwks) => {
    if (!jwks ||
        !Array.isArray(jwks.keys) ||
        jwks.keys.length === 0 ||
        jwks.keys.length > MAX_JWK_KEYS) {
        throw new Error(`JWKS must contain between 1 and ${MAX_JWK_KEYS} public keys`);
    }
    const kids = new Set();
    for (const key of jwks.keys) {
        if (!key || typeof key !== "object") {
            throw new Error("JWKS contains an invalid key");
        }
        assertBoundedClaim(key.kid, "JWKS kid", MAX_KID_LENGTH);
        if (kids.has(key.kid)) {
            throw new Error(`JWKS contains a duplicate kid: ${key.kid}`);
        }
        kids.add(key.kid);
        if (key.kty !== "EC" || key.crv !== "P-256" || key.d !== undefined) {
            throw new Error(`JWKS key ${key.kid} must be a public P-256 EC key`);
        }
        assertP256Component(key.x, "x coordinate", key.kid);
        assertP256Component(key.y, "y coordinate", key.kid);
        if (key.alg && key.alg !== exports.ACCESS_TOKEN_ALGORITHM) {
            throw new Error(`JWKS key ${key.kid} must use ${exports.ACCESS_TOKEN_ALGORITHM}`);
        }
        if (key.use && key.use !== "sig") {
            throw new Error(`JWKS key ${key.kid} must declare use=sig`);
        }
        if (key.key_ops && !key.key_ops.includes("verify")) {
            throw new Error(`JWKS key ${key.kid} has incompatible key_ops`);
        }
    }
};
//# sourceMappingURL=jwk.js.map