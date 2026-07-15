"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.verifyAccessTokenWithJwks = exports.generateSigningJwk = exports.JwtKeyRing = exports.DEFAULT_TOKEN_AUDIENCE = exports.DEFAULT_TOKEN_ISSUER = exports.LEGACY_TOKEN_ALGORITHM = exports.ACCESS_TOKEN_ALGORITHM = exports.loadJose = void 0;
const crypto_1 = require("crypto");
const loadJose = () => import("jose");
exports.loadJose = loadJose;
exports.ACCESS_TOKEN_ALGORITHM = "ES256";
exports.LEGACY_TOKEN_ALGORITHM = "HS256";
exports.DEFAULT_TOKEN_ISSUER = "authenik8-core";
exports.DEFAULT_TOKEN_AUDIENCE = "authenik8-api";
const PRIVATE_JWK_FIELDS = new Set([
    "d",
    "p",
    "q",
    "dp",
    "dq",
    "qi",
    "oth",
    "k",
]);
const assertCanonicalCompactJwt = (token) => {
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
const publicJwk = (key) => {
    const result = Object.fromEntries(Object.entries(key).filter(([name]) => !PRIVATE_JWK_FIELDS.has(name)));
    return {
        ...result,
        alg: exports.ACCESS_TOKEN_ALGORITHM,
        use: "sig",
        key_ops: ["verify"],
    };
};
const validateJwkConfig = (config) => {
    if (!config.issuer.trim())
        throw new Error("jwt.issuer is required");
    const audiences = Array.isArray(config.audience)
        ? config.audience
        : [config.audience];
    if (!audiences.length || audiences.some((audience) => !audience.trim())) {
        throw new Error("jwt.audience must contain at least one non-empty value");
    }
    if (!config.activeKid.trim())
        throw new Error("jwt.activeKid is required");
    if (!config.keys.length)
        throw new Error("jwt.keys must contain at least one key");
    const kids = new Set();
    for (const key of config.keys) {
        if (!key.kid)
            throw new Error("Every JWT signing key must have a kid");
        if (kids.has(key.kid))
            throw new Error(`Duplicate JWT kid: ${key.kid}`);
        kids.add(key.kid);
        if (key.kty !== "EC" || key.crv !== "P-256") {
            throw new Error(`JWT key ${key.kid} must be an ES256 P-256 EC JWK`);
        }
        if (!key.x || !key.y) {
            throw new Error(`JWT key ${key.kid} must include x and y coordinates`);
        }
        if (key.alg && key.alg !== exports.ACCESS_TOKEN_ALGORITHM) {
            throw new Error(`JWT key ${key.kid} must use ${exports.ACCESS_TOKEN_ALGORITHM}`);
        }
    }
    const activeKey = config.keys.find((key) => key.kid === config.activeKid);
    if (!activeKey)
        throw new Error(`Active JWT kid not found: ${config.activeKid}`);
    if (!activeKey.d)
        throw new Error(`Active JWT key ${config.activeKid} must be private`);
};
class JwtKeyRing {
    constructor(options) {
        if (options.jwk) {
            validateJwkConfig(options.jwk);
            this.jwk = options.jwk;
            this.issuer = options.jwk.issuer;
            this.audience = options.jwk.audience;
            return;
        }
        if (!options.legacySecret) {
            throw new Error("Configure jwt.keys or provide the deprecated jwtSecret");
        }
        this.legacySecret = new TextEncoder().encode(options.legacySecret);
        this.issuer = options.issuer ?? exports.DEFAULT_TOKEN_ISSUER;
        this.audience = options.audience ?? exports.DEFAULT_TOKEN_AUDIENCE;
    }
    async sign(payload, options) {
        const { SignJWT } = await (0, exports.loadJose)();
        const jwt = new SignJWT({ ...payload, tokenUse: options.tokenUse })
            .setProtectedHeader(this.protectedHeader())
            .setIssuer(this.issuer)
            .setAudience(this.audience)
            .setIssuedAt()
            .setJti((0, crypto_1.randomUUID)())
            .setExpirationTime(options.expiresIn);
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
            });
        // Pre-JOSE legacy tokens did not carry tokenUse. The asymmetric path always
        // requires it, while HS256 accepts the missing claim during migration.
        if (payload.tokenUse !== tokenUse &&
            (this.jwk || payload.tokenUse !== undefined)) {
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
    const { createLocalJWKSet, createRemoteJWKSet, jwtVerify } = await (0, exports.loadJose)();
    const resolver = jwks instanceof URL
        ? createRemoteJWKSet(jwks)
        : createLocalJWKSet(jwks);
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
//# sourceMappingURL=jwk.js.map