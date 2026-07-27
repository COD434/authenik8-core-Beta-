import { randomUUID } from "crypto";
import type { JSONWebKeySet, JWK, JWTPayload } from "jose" with {
  "resolution-mode": "import"
};
import { containsControlCharacter } from "../utility/safeString";

type JoseModule = typeof import("jose", {
  with: { "resolution-mode": "import" }
});
export const loadJose = (): Promise<JoseModule> => import("jose");

export const ACCESS_TOKEN_ALGORITHM = "ES256" as const;
export const LEGACY_TOKEN_ALGORITHM = "HS256" as const;
export const DEFAULT_TOKEN_ISSUER = "authenik8-core";
export const DEFAULT_TOKEN_AUDIENCE = "authenik8-api";
export const MINIMUM_HMAC_SECRET_BYTES = 32;
const MAX_COMPACT_JWT_LENGTH = 16 * 1024;
const MAX_JWK_KEYS = 16;
const MAX_ISSUER_LENGTH = 2048;
const MAX_AUDIENCES = 32;
const MAX_AUDIENCE_LENGTH = 512;
const MAX_KID_LENGTH = 128;
const MAX_GENERIC_TOKEN_TTL_SECONDS = 31 * 24 * 60 * 60;

export type Authenik8TokenUse =
  | "access"
  | "guest"
  | "refresh"
  | "agent"
  | "agent-delegation";

export interface Authenik8JwkConfig {
  keys: JWK[];
  activeKid: string;
  issuer: string;
  audience: string | string[];
}

export interface JwtKeyRingOptions {
  jwk?: Authenik8JwkConfig;
  legacySecret?: string;
  issuer?: string;
  audience?: string | string[];
}

export interface SignJwtOptions {
  expiresInSeconds: number;
  tokenUse: Authenik8TokenUse;
}

export interface PublicJwksVerificationOptions {
  issuer: string;
  audience: string | string[];
}

const assertCanonicalCompactJwt = (token: string): void => {
  if (!token || token.length > MAX_COMPACT_JWT_LENGTH) {
    throw new Error(
      `JWT must be between 1 and ${MAX_COMPACT_JWT_LENGTH} characters`,
    );
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

const hmacSecret = (secret: string, label: string): Uint8Array => {
  const encoded = new TextEncoder().encode(secret);
  if (
    encoded.length < MINIMUM_HMAC_SECRET_BYTES ||
    encoded.length > 4096
  ) {
    throw new Error(
      `${label} must contain between ${MINIMUM_HMAC_SECRET_BYTES} and 4096 bytes of cryptographically random material`,
    );
  }
  return encoded;
};

export const normalizeTokenLifetime = (
  value: string | number,
  label: string,
  minimumSeconds: number,
  maximumSeconds: number,
): number => {
  let seconds: number;
  if (typeof value === "number") {
    seconds = value;
  } else {
    const match = /^(\d+)([smhd])$/.exec(value);
    if (!match) {
      throw new Error(`${label} must use a whole-number s, m, h, or d duration`);
    }
    const amount = Number(match[1]);
    const multiplier =
      match[2] === "s"
        ? 1
        : match[2] === "m"
          ? 60
          : match[2] === "h"
            ? 3600
            : 86400;
    seconds = amount * multiplier;
  }
  if (
    !Number.isSafeInteger(seconds) ||
    seconds < minimumSeconds ||
    seconds > maximumSeconds
  ) {
    throw new Error(
      `${label} must be between ${minimumSeconds} and ${maximumSeconds} seconds`,
    );
  }
  return seconds;
};

const assertBoundedClaim: (
  value: unknown,
  label: string,
  maximumLength: number,
) => asserts value is string = (value, label, maximumLength) => {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > maximumLength ||
    containsControlCharacter(value)
  ) {
    throw new Error(`${label} is invalid or exceeds ${maximumLength} characters`);
  }
};

const validateIssuerAndAudience = (
  issuer: unknown,
  audience: unknown,
  prefix: string,
): void => {
  assertBoundedClaim(issuer, `${prefix}.issuer`, MAX_ISSUER_LENGTH);
  const audiences = Array.isArray(audience) ? audience : [audience];
  if (
    audiences.length === 0 ||
    audiences.length > MAX_AUDIENCES
  ) {
    throw new Error(
      `${prefix}.audience must contain between 1 and ${MAX_AUDIENCES} values`,
    );
  }
  audiences.forEach((entry) =>
    assertBoundedClaim(
      entry,
      `${prefix}.audience`,
      MAX_AUDIENCE_LENGTH,
    ),
  );
};

const assertP256Component = (
  value: unknown,
  label: string,
  kid: string,
): void => {
  if (typeof value !== "string") {
    throw new Error(`JWT key ${kid} must include ${label}`);
  }
  const decoded = Buffer.from(value, "base64url");
  if (
    decoded.length !== 32 ||
    decoded.toString("base64url") !== value
  ) {
    throw new Error(`JWT key ${kid} has an invalid P-256 ${label} value`);
  }
};

const publicJwk = (key: JWK): JWK => {
  return {
    kty: key.kty,
    crv: key.crv,
    x: key.x,
    y: key.y,
    kid: key.kid,
    alg: ACCESS_TOKEN_ALGORITHM,
    use: "sig",
    key_ops: ["verify"],
  };
};

const validateJwkConfig = (config: Authenik8JwkConfig): void => {
  validateIssuerAndAudience(config.issuer, config.audience, "jwt");
  assertBoundedClaim(config.activeKid, "jwt.activeKid", MAX_KID_LENGTH);
  if (!config.keys.length || config.keys.length > MAX_JWK_KEYS) {
    throw new Error(`jwt.keys must contain between 1 and ${MAX_JWK_KEYS} keys`);
  }

  const kids = new Set<string>();
  for (const key of config.keys) {
    if (!key.kid) throw new Error("Every JWT signing key must have a kid");
    assertBoundedClaim(key.kid, "JWT kid", MAX_KID_LENGTH);
    if (kids.has(key.kid)) throw new Error(`Duplicate JWT kid: ${key.kid}`);
    kids.add(key.kid);

    if (key.kty !== "EC" || key.crv !== "P-256") {
      throw new Error(`JWT key ${key.kid} must be an ES256 P-256 EC JWK`);
    }
    assertP256Component(key.x, "x coordinate", key.kid);
    assertP256Component(key.y, "y coordinate", key.kid);
    if (key.d !== undefined) {
      assertP256Component(key.d, "private scalar", key.kid);
    }
    if (key.alg && key.alg !== ACCESS_TOKEN_ALGORITHM) {
      throw new Error(`JWT key ${key.kid} must use ${ACCESS_TOKEN_ALGORITHM}`);
    }
    if (key.use && key.use !== "sig") {
      throw new Error(`JWT key ${key.kid} must declare use=sig`);
    }
    if (
      key.key_ops &&
      !key.key_ops.includes(key.d ? "sign" : "verify")
    ) {
      throw new Error(`JWT key ${key.kid} has incompatible key_ops`);
    }
  }

  const activeKey = config.keys.find((key) => key.kid === config.activeKid);
  if (!activeKey) throw new Error(`Active JWT kid not found: ${config.activeKid}`);
  if (!activeKey.d) throw new Error(`Active JWT key ${config.activeKid} must be private`);
};

const cloneJwkConfig = (
  config: Authenik8JwkConfig,
): Authenik8JwkConfig => ({
  ...config,
  audience: Array.isArray(config.audience)
    ? [...config.audience]
    : config.audience,
  keys: config.keys.map((key) => ({
    ...key,
    ...(key.key_ops ? { key_ops: [...key.key_ops] } : {}),
  })),
});

export class JwtKeyRing {
  readonly issuer: string;
  readonly audience: string | string[];
  private readonly jwk?: Authenik8JwkConfig;
  private readonly legacySecret?: Uint8Array;

  constructor(options: JwtKeyRingOptions) {
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
    this.issuer = options.issuer ?? DEFAULT_TOKEN_ISSUER;
    this.audience = options.audience ?? DEFAULT_TOKEN_AUDIENCE;
    validateIssuerAndAudience(this.issuer, this.audience, "jwt");
  }

  async sign(
    payload: Record<string, unknown>,
    options: SignJwtOptions,
  ): Promise<string> {
    if (
      !Number.isSafeInteger(options.expiresInSeconds) ||
      options.expiresInSeconds < 1 ||
      options.expiresInSeconds > MAX_GENERIC_TOKEN_TTL_SECONDS
    ) {
      throw new Error(
        `JWT expiry must be between 1 and ${MAX_GENERIC_TOKEN_TTL_SECONDS} seconds`,
      );
    }
    const { SignJWT } = await loadJose();
    const now = Math.floor(Date.now() / 1000);
    const jwt = new SignJWT({ ...payload, tokenUse: options.tokenUse })
      .setProtectedHeader(this.protectedHeader())
      .setIssuer(this.issuer)
      .setAudience(this.audience)
      .setIssuedAt(now)
      .setJti(randomUUID())
      .setExpirationTime(now + options.expiresInSeconds);

    if (this.jwk) {
      return jwt.sign(this.activePrivateJwk());
    }

    return jwt.sign(this.legacySecret!);
  }

  async verify<T extends JWTPayload = JWTPayload>(
    token: string,
    tokenUse: Authenik8TokenUse,
  ): Promise<T> {
    assertCanonicalCompactJwt(token);
    const { createLocalJWKSet, jwtVerify } = await loadJose();
    const { payload } = this.jwk
      ? await jwtVerify<T>(token, createLocalJWKSet(this.getJwks()), {
          algorithms: [ACCESS_TOKEN_ALGORITHM],
          issuer: this.issuer,
          audience: this.audience,
        })
      : await jwtVerify<T>(token, this.legacySecret!, {
          algorithms: [LEGACY_TOKEN_ALGORITHM],
          issuer: this.issuer,
          audience: this.audience,
        });

    if (payload.tokenUse !== tokenUse) {
      throw new Error(`Expected a ${tokenUse} token`);
    }

    return payload;
  }

  getJwks(): JSONWebKeySet {
    return {
      keys: this.jwk?.keys.map(publicJwk) ?? [],
    };
  }

  private activePrivateJwk(): JWK {
    return this.jwk!.keys.find((key) => key.kid === this.jwk!.activeKid)!;
  }

  private protectedHeader() {
    return this.jwk
      ? { alg: ACCESS_TOKEN_ALGORITHM, kid: this.jwk.activeKid, typ: "JWT" }
      : { alg: LEGACY_TOKEN_ALGORITHM, kid: "legacy-hs256", typ: "JWT" };
  }
}

export const decodeBoundedJwt = async <
  T extends JWTPayload = JWTPayload,
>(token: string): Promise<T> => {
  assertCanonicalCompactJwt(token);
  const { decodeJwt } = await loadJose();
  return decodeJwt(token) as T;
};

export const generateSigningJwk = async (kid?: string): Promise<JWK> => {
  const { calculateJwkThumbprint, exportJWK, generateKeyPair } = await loadJose();
  const { privateKey, publicKey } = await generateKeyPair(ACCESS_TOKEN_ALGORITHM, {
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
    alg: ACCESS_TOKEN_ALGORITHM,
    use: "sig",
    key_ops: ["sign"],
    kid: resolvedKid,
  };
};

export const verifyAccessTokenWithJwks = async <
  T extends JWTPayload = JWTPayload,
>(
  token: string,
  jwks: JSONWebKeySet | URL,
  options: PublicJwksVerificationOptions,
): Promise<T> => {
  assertCanonicalCompactJwt(token);
  validateIssuerAndAudience(
    options.issuer,
    options.audience,
    "verification",
  );
  const { createLocalJWKSet, createRemoteJWKSet, jwtVerify } = await loadJose();
  let resolver;
  if (jwks instanceof URL) {
    if (
      jwks.protocol !== "https:" ||
      jwks.username ||
      jwks.password ||
      jwks.hash
    ) {
      throw new Error("Remote JWKS URLs must use credential-free HTTPS");
    }
    resolver = createRemoteJWKSet(jwks);
  } else {
    validatePublicJwks(jwks);
    resolver = createLocalJWKSet(jwks);
  }
  const { payload } = await jwtVerify<T>(token, resolver, {
    algorithms: [ACCESS_TOKEN_ALGORITHM],
    issuer: options.issuer,
    audience: options.audience,
  });

  if (payload.tokenUse !== "access") {
    throw new Error("Expected an access token");
  }
  return payload;
};

const validatePublicJwks = (jwks: JSONWebKeySet): void => {
  if (
    !jwks ||
    !Array.isArray(jwks.keys) ||
    jwks.keys.length === 0 ||
    jwks.keys.length > MAX_JWK_KEYS
  ) {
    throw new Error(
      `JWKS must contain between 1 and ${MAX_JWK_KEYS} public keys`,
    );
  }

  const kids = new Set<string>();
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
    if (key.alg && key.alg !== ACCESS_TOKEN_ALGORITHM) {
      throw new Error(`JWKS key ${key.kid} must use ${ACCESS_TOKEN_ALGORITHM}`);
    }
    if (key.use && key.use !== "sig") {
      throw new Error(`JWKS key ${key.kid} must declare use=sig`);
    }
    if (key.key_ops && !key.key_ops.includes("verify")) {
      throw new Error(`JWKS key ${key.kid} has incompatible key_ops`);
    }
  }
};
