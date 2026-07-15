import { randomUUID } from "crypto";
import type { JSONWebKeySet, JWK, JWTPayload } from "jose" with {
  "resolution-mode": "import"
};

type JoseModule = typeof import("jose", {
  with: { "resolution-mode": "import" }
});
export const loadJose = (): Promise<JoseModule> => import("jose");

export const ACCESS_TOKEN_ALGORITHM = "ES256" as const;
export const LEGACY_TOKEN_ALGORITHM = "HS256" as const;
export const DEFAULT_TOKEN_ISSUER = "authenik8-core";
export const DEFAULT_TOKEN_AUDIENCE = "authenik8-api";

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
  expiresIn: string | number;
  tokenUse: Authenik8TokenUse;
}

export interface PublicJwksVerificationOptions {
  issuer: string;
  audience: string | string[];
}

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

const assertCanonicalCompactJwt = (token: string): void => {
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

const publicJwk = (key: JWK): JWK => {
  const result = Object.fromEntries(
    Object.entries(key).filter(([name]) => !PRIVATE_JWK_FIELDS.has(name)),
  ) as JWK;

  return {
    ...result,
    alg: ACCESS_TOKEN_ALGORITHM,
    use: "sig",
    key_ops: ["verify"],
  };
};

const validateJwkConfig = (config: Authenik8JwkConfig): void => {
  if (!config.issuer.trim()) throw new Error("jwt.issuer is required");
  const audiences = Array.isArray(config.audience)
    ? config.audience
    : [config.audience];
  if (!audiences.length || audiences.some((audience) => !audience.trim())) {
    throw new Error("jwt.audience must contain at least one non-empty value");
  }
  if (!config.activeKid.trim()) throw new Error("jwt.activeKid is required");
  if (!config.keys.length) throw new Error("jwt.keys must contain at least one key");

  const kids = new Set<string>();
  for (const key of config.keys) {
    if (!key.kid) throw new Error("Every JWT signing key must have a kid");
    if (kids.has(key.kid)) throw new Error(`Duplicate JWT kid: ${key.kid}`);
    kids.add(key.kid);

    if (key.kty !== "EC" || key.crv !== "P-256") {
      throw new Error(`JWT key ${key.kid} must be an ES256 P-256 EC JWK`);
    }
    if (!key.x || !key.y) {
      throw new Error(`JWT key ${key.kid} must include x and y coordinates`);
    }
    if (key.alg && key.alg !== ACCESS_TOKEN_ALGORITHM) {
      throw new Error(`JWT key ${key.kid} must use ${ACCESS_TOKEN_ALGORITHM}`);
    }
  }

  const activeKey = config.keys.find((key) => key.kid === config.activeKid);
  if (!activeKey) throw new Error(`Active JWT kid not found: ${config.activeKid}`);
  if (!activeKey.d) throw new Error(`Active JWT key ${config.activeKid} must be private`);
};

export class JwtKeyRing {
  readonly issuer: string;
  readonly audience: string | string[];
  private readonly jwk?: Authenik8JwkConfig;
  private readonly legacySecret?: Uint8Array;

  constructor(options: JwtKeyRingOptions) {
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
    this.issuer = options.issuer ?? DEFAULT_TOKEN_ISSUER;
    this.audience = options.audience ?? DEFAULT_TOKEN_AUDIENCE;
  }

  async sign(
    payload: Record<string, unknown>,
    options: SignJwtOptions,
  ): Promise<string> {
    const { SignJWT } = await loadJose();
    const jwt = new SignJWT({ ...payload, tokenUse: options.tokenUse })
      .setProtectedHeader(this.protectedHeader())
      .setIssuer(this.issuer)
      .setAudience(this.audience)
      .setIssuedAt()
      .setJti(randomUUID())
      .setExpirationTime(options.expiresIn);

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
        });

    // Pre-JOSE legacy tokens did not carry tokenUse. The asymmetric path always
    // requires it, while HS256 accepts the missing claim during migration.
    if (
      payload.tokenUse !== tokenUse &&
      (this.jwk || payload.tokenUse !== undefined)
    ) {
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
  const { createLocalJWKSet, createRemoteJWKSet, jwtVerify } = await loadJose();
  const resolver = jwks instanceof URL
    ? createRemoteJWKSet(jwks)
    : createLocalJWKSet(jwks);
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
