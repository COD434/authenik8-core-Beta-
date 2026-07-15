import httpMocks from "node-mocks-http";
import {
  createLocalJWKSet,
  decodeJwt,
  decodeProtectedHeader,
  jwtVerify,
} from "jose";
import { vi } from "vitest";
import {
  generateSigningJwk,
  verifyAccessTokenWithJwks,
} from "../../auth/jwk";
import { JWTService } from "../../auth/jwtAuth";

const SECRET = "test-secret";
const WRONG_SECRET = "wrong-secret";
const BASE64URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

const mockRedis = {
  store: new Map<string, Record<string, string>>(),
  async hgetall(key: string) {
    return this.store.get(key) ?? null;
  },
  async hset(key: string, field: string, value: string) {
    const hash = this.store.get(key) ?? {};
    hash[field] = value;
    this.store.set(key, hash);
  },
  async hdel(key: string, field: string) {
    const hash = this.store.get(key);
    if (hash) delete hash[field];
  },
  async expire(_key: string, _ttl: number) {},
  clear() {
    this.store.clear();
  },
};

const makeService = (withRedis = false, allowCookieAuth = false) =>
  new JWTService({
    jwtSecret: SECRET,
    expiry: "1h",
    redisClient: withRedis ? mockRedis : undefined,
    allowCookieAuth,
  });

describe("JOSE token signing and verification", () => {
  it("produces a verified access token with required claims", async () => {
    const svc = makeService();
    const token = await svc.signToken({ userId: "u1", email: "a@b.com" });
    const decoded = await svc.verifyToken(token);

    expect(decoded).toMatchObject({
      userId: "u1",
      tokenUse: "access",
      iss: "authenik8-core",
      aud: "authenik8-api",
    });
    expect(decoded?.jti).toEqual(expect.any(String));
  });

  it("defaults access tokens to a one-hour expiry", async () => {
    const token = await new JWTService({ jwtSecret: SECRET }).signToken({
      userId: "u1",
      email: "a@b.com",
    });
    const decoded = decodeJwt(token);
    expect(decoded.exp! - decoded.iat!).toBeLessThanOrEqual(3600);
  });

  it("rejects a token signed with the wrong key", async () => {
    const token = await new JWTService({ jwtSecret: WRONG_SECRET }).signToken({
      userId: "u1",
      email: "a@b.com",
    });
    await expect(makeService().verifyToken(token)).resolves.toBeNull();
  });

  it("rejects an expired token", async () => {
    const token = await new JWTService({
      jwtSecret: SECRET,
      expiry: "-1s",
    }).signToken({ userId: "u1", email: "a@b.com" });
    await expect(makeService().verifyToken(token)).resolves.toBeNull();
  });

  it("rejects alg:none, tampered, and malformed tokens", async () => {
    const header = Buffer.from(JSON.stringify({ alg: "none", typ: "JWT" })).toString(
      "base64url",
    );
    const payload = Buffer.from(
      JSON.stringify({ userId: "u1", email: "a@b.com" }),
    ).toString("base64url");
    await expect(makeService().verifyToken(`${header}.${payload}.`)).resolves.toBeNull();

    const token = await makeService().signToken({ userId: "u1", email: "a@b.com" });
    const [protectedHeader, , signature] = token.split(".");
    const tampered = Buffer.from(JSON.stringify({ userId: "admin" })).toString(
      "base64url",
    );
    await expect(
      makeService().verifyToken(`${protectedHeader}.${tampered}.${signature}`),
    ).resolves.toBeNull();
    await expect(makeService().verifyToken("not.a.token")).resolves.toBeNull();
  });

  it("does not accept a guest token as an access token", async () => {
    const svc = makeService();
    const token = await svc.guestToken();
    await expect(svc.verifyToken(token)).resolves.toBeNull();
    await expect(svc.verifyGuestToken(token)).resolves.toMatchObject({ type: "guest" });
  });
});

describe("ES256 JWK and rotation", () => {
  it("fails fast on incomplete JWK configuration", async () => {
    const signingKey = await generateSigningJwk("validation-key");

    expect(() => new JWTService({
      jwk: {
        keys: [signingKey],
        activeKid: "validation-key",
        issuer: "https://issuer.example",
        audience: "",
      },
    })).toThrow("jwt.audience");

    expect(() => new JWTService({
      jwk: {
        keys: [{ ...signingKey, x: undefined }],
        activeKid: "validation-key",
        issuer: "https://issuer.example",
        audience: "example-api",
      },
    })).toThrow("x and y coordinates");
  });

  it("publishes public keys and verifies with kid, issuer, and audience", async () => {
    const signingKey = await generateSigningJwk("current-key");
    const svc = new JWTService({
      jwk: {
        keys: [signingKey],
        activeKid: "current-key",
        issuer: "https://issuer.example",
        audience: "example-api",
      },
    });
    const token = await svc.signToken({ userId: "u1", email: "a@b.com" });
    const header = decodeProtectedHeader(token);
    const jwks = svc.getJwks();

    expect(header).toMatchObject({ alg: "ES256", kid: "current-key", typ: "JWT" });
    expect(jwks.keys[0]).not.toHaveProperty("d");
    await expect(
      jwtVerify(token, createLocalJWKSet(jwks), {
        algorithms: ["ES256"],
        issuer: "https://issuer.example",
        audience: "example-api",
      }),
    ).resolves.toMatchObject({ payload: { userId: "u1" } });
    await expect(
      jwtVerify(token, createLocalJWKSet(jwks), {
        issuer: "https://wrong.example",
        audience: "example-api",
      }),
    ).rejects.toThrow();
    await expect(
      verifyAccessTokenWithJwks(token, jwks, {
        issuer: "https://issuer.example",
        audience: "example-api",
      }),
    ).resolves.toMatchObject({ userId: "u1", tokenUse: "access" });
  });

  it("rejects non-canonical compact token encodings", async () => {
    const signingKey = await generateSigningJwk("canonical-key");
    const config = {
      keys: [signingKey],
      activeKid: "canonical-key",
      issuer: "https://issuer.example",
      audience: "example-api",
    };
    const svc = new JWTService({ jwk: config });
    const token = await svc.signToken({ userId: "u1" });
    const segments = token.split(".");
    const signature = segments[2]!;
    const finalIndex = BASE64URL.indexOf(signature[signature.length - 1]!);
    segments[2] = `${signature.slice(0, -1)}${BASE64URL[finalIndex ^ 1]}`;
    const nonCanonicalToken = segments.join(".");

    expect(Buffer.from(segments[2]!, "base64url")).toEqual(
      Buffer.from(signature, "base64url"),
    );
    await expect(svc.verifyToken(nonCanonicalToken)).resolves.toBeNull();
    await expect(
      verifyAccessTokenWithJwks(nonCanonicalToken, svc.getJwks(), config),
    ).rejects.toThrow("non-canonical");
  });

  it("keeps old tokens verifiable while a new kid signs new tokens", async () => {
    const oldKey = await generateSigningJwk("old-key");
    const newKey = await generateSigningJwk("new-key");
    const base = { issuer: "issuer", audience: "api" };
    const oldService = new JWTService({
      jwk: { ...base, keys: [oldKey], activeKid: "old-key" },
    });
    const oldToken = await oldService.signToken({ userId: "u1" });
    const rotatedService = new JWTService({
      jwk: { ...base, keys: [newKey, oldKey], activeKid: "new-key" },
    });
    const newToken = await rotatedService.signToken({ userId: "u1" });

    await expect(rotatedService.verifyToken(oldToken)).resolves.toMatchObject({ userId: "u1" });
    expect(decodeProtectedHeader(newToken).kid).toBe("new-key");
  });
});

describe("guestToken", () => {
  it("issues unique guest identities and invokes the callback", async () => {
    const cb = vi.fn();
    const svc = new JWTService({ jwtSecret: SECRET, expiry: "1h", onGuestToken: cb });
    const first = decodeJwt(await svc.guestToken());
    const second = decodeJwt(await svc.guestToken());
    expect(first.type).toBe("guest");
    expect(first.id).not.toBe(second.id);
    expect(cb).toHaveBeenCalledTimes(2);
  });
});

describe("authenticateJWT middleware", () => {
  beforeEach(() => mockRedis.clear());

  const run = async (
    svc: JWTService,
    token: string | null,
    via: "bearer" | "cookie" = "bearer",
  ) => {
    const req = httpMocks.createRequest({
      headers: via === "bearer" && token ? { authorization: `Bearer ${token}` } : {},
      cookies: via === "cookie" && token ? { token } : {},
    });
    const res = httpMocks.createResponse();
    const next = vi.fn();
    await svc.authenticateJWT(req, res, next);
    return { req, res, next };
  };

  it("accepts Bearer tokens and only accepts cookies when enabled", async () => {
    const svc = makeService();
    const token = await svc.signToken({ userId: "u1", email: "a@b.com" });
    expect((await run(svc, token)).next).toHaveBeenCalled();
    expect((await run(svc, token, "cookie")).res.statusCode).toBe(401);
    expect((await run(makeService(false, true), token, "cookie")).next).toHaveBeenCalled();
  });

  it("returns 401 without a token and 403 for invalid tokens", async () => {
    expect((await run(makeService(), null)).res.statusCode).toBe(401);
    expect((await run(makeService(), "not.a.token")).res.statusCode).toBe(403);
  });

  it("rejects a valid signature when the stored session does not match", async () => {
    const svc = makeService(true);
    const realToken = await svc.signToken({ userId: "u1", email: "a@b.com" });
    const payload = decodeJwt(realToken);
    const stolenToken = await makeService().signToken({
      userId: "u1",
      email: "a@b.com",
      sessionId: payload.sessionId as string,
    });

    const { res, next } = await run(svc, stolenToken);
    expect(res.statusCode).toBe(403);
    expect(next).not.toHaveBeenCalled();
  });

  it("accepts the stored token, attaches its user, then rejects it after revocation", async () => {
    const svc = makeService(true);
    const token = await svc.signToken({ userId: "u1", email: "a@b.com" });
    const accepted = await run(svc, token);
    expect(accepted.next).toHaveBeenCalled();
    expect((accepted.req as any).user.userId).toBe("u1");

    await svc.revokeSession("u1", decodeJwt(token).sessionId as string);
    const revoked = await run(svc, token);
    expect(revoked.res.statusCode).toBe(403);
    expect(revoked.next).not.toHaveBeenCalled();
  });
});
