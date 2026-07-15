import type { NextFunction, Request, Response } from "express";
import jwt from "jsonwebtoken";
import { afterEach, describe, expect, test, vi } from "vitest";
import { JWTService } from "../../auth/jwtAuth";
import { requireAdmin } from "../../middleware/adminService";
import { createGitHubProvider } from "../../oauth/providers/github";
import { createGoogleProvider } from "../../oauth/providers/google";
import type { OAuthStateStore } from "../../oauth/types";
import { SecurityModule } from "../../security/ipService";

/*
 * Reproducible security fuzzing.
 *
 * Defaults are deliberately small enough for every CI run. To replay or deepen
 * a run:
 *
 *   FUZZ_SEED=0x5eed1234 FUZZ_RUNS=10000 \
 *     npx vitest run --config vitest.config.ts \
 *     src/tests/Sectests/adversarial.fuzz.test.ts
 */
const DEFAULT_SEED = 0x5eed1234;
const DEFAULT_RUNS = 500;
const MAX_RUNS = 10_000;
const JWT_SECRET = "fuzz-only-secret-that-is-not-used-outside-this-test";
const BASE64URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const HOSTILE_TEXT = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789:/?&=%._-";

const envInteger = (name: string, fallback: number): number => {
  const parsed = Number(process.env[name]);
  return Number.isSafeInteger(parsed) ? parsed : fallback;
};

const FUZZ_SEED = envInteger("FUZZ_SEED", DEFAULT_SEED) >>> 0;
const FUZZ_RUNS = Math.min(
  Math.max(envInteger("FUZZ_RUNS", DEFAULT_RUNS), 1),
  MAX_RUNS
);

type Fuzzer = ReturnType<typeof createFuzzer>;

function createFuzzer(seed: number) {
  let state = seed || 0x9e3779b9;

  const next = (): number => {
    // xorshift32: deterministic, fast, and sufficient for input generation.
    state ^= state << 13;
    state ^= state >>> 17;
    state ^= state << 5;
    return state >>> 0;
  };

  const integer = (upperExclusive: number): number =>
    upperExclusive <= 1 ? 0 : next() % upperExclusive;

  const text = (
    minimumLength: number,
    maximumLength: number,
    alphabet = HOSTILE_TEXT
  ): string => {
    const length =
      minimumLength + integer(maximumLength - minimumLength + 1);
    let value = "";

    for (let index = 0; index < length; index += 1) {
      value += alphabet[integer(alphabet.length)]!;
    }

    return value;
  };

  return { integer, next, text };
}

const replay = (target: string, iteration: number, input: string): string =>
  [
    `${target} failed`,
    `seed=0x${FUZZ_SEED.toString(16)}`,
    `iteration=${iteration}`,
    `input=${JSON.stringify(input)}`,
  ].join(" ");

const encodeJson = (value: unknown): string =>
  Buffer.from(JSON.stringify(value)).toString("base64url");

function mutateCompactJwt(token: string, fuzzer: Fuzzer, iteration: number): string {
  const segments = token.split(".");
  const segmentIndex = iteration % 3;
  const segment = segments[segmentIndex]!;
  const offset = fuzzer.integer(segment.length);
  const current = segment[offset]!;
  let replacement = BASE64URL[fuzzer.integer(BASE64URL.length)]!;

  if (replacement === current) {
    replacement = BASE64URL[(BASE64URL.indexOf(replacement) + 1) % BASE64URL.length]!;
  }

  segments[segmentIndex] =
    segment.slice(0, offset) + replacement + segment.slice(offset + 1);
  return segments.join(".");
}

function malformedJwt(fuzzer: Fuzzer): string {
  const segment = () => fuzzer.text(0, 192, BASE64URL);
  const payload = encodeJson({
    userId: "victim",
    role: "admin",
    noise: fuzzer.text(0, 64),
  });

  switch (fuzzer.integer(8)) {
    case 0:
      return fuzzer.text(0, 512);
    case 1:
      return `${segment()}.${segment()}`;
    case 2:
      return `${segment()}.${segment()}.${segment()}.${segment()}`;
    case 3:
      return `${encodeJson({ alg: "none", typ: "JWT" })}.${payload}.`;
    case 4:
      return `${encodeJson({ alg: "HS256", typ: "JWT" })}.${payload}.${segment()}`;
    case 5:
      return `${encodeJson({ alg: fuzzer.text(1, 24), typ: "JWT" })}.${payload}.${segment()}`;
    case 6:
      return `.${payload}.${segment()}`;
    default:
      return `${segment()}..${segment()}`;
  }
}

type MiddlewareResult = {
  nextCalled: boolean;
  statusCode: number;
  body: unknown;
};

async function invokeMiddleware(
  middleware: (req: Request, res: Response, next: NextFunction) => unknown,
  authorization?: string
): Promise<MiddlewareResult> {
  const req = {
    headers: authorization === undefined ? {} : { authorization },
    cookies: {},
    socket: {},
  } as unknown as Request;
  const result: MiddlewareResult = {
    nextCalled: false,
    statusCode: 200,
    body: undefined,
  };
  const res = {
    status(code: number) {
      result.statusCode = code;
      return this;
    },
    json(body: unknown) {
      result.body = body;
      return this;
    },
    send(body: unknown) {
      result.body = body;
      return this;
    },
  } as unknown as Response;

  await middleware(req, res, () => {
    result.nextCalled = true;
  });

  return result;
}

function fakeWhitelistRedis(entries: string[]) {
  const activeEntries = new Set(entries);

  return {
    on() {},
    async sismember(_key: string, value: string) {
      return activeEntries.has(value) ? 1 : 0;
    },
    async smembers() {
      return [...activeEntries];
    },
    async exists() {
      return 1;
    },
    async srem() {
      return 1;
    },
  };
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("adversarial fuzzing", () => {
  test("rejects forged, unsigned, truncated, and bit-flipped JWTs", async () => {
    const fuzzer = createFuzzer(FUZZ_SEED ^ 0x4a5754);
    const service = new JWTService({ jwtSecret: JWT_SECRET });
    const validToken = jwt.sign(
      { userId: "victim", role: "admin", sessionId: "known-session" },
      JWT_SECRET,
      { algorithm: "HS256", expiresIn: "1h" }
    );

    for (let iteration = 0; iteration < FUZZ_RUNS; iteration += 1) {
      const input =
        iteration % 2 === 0
          ? mutateCompactJwt(validToken, fuzzer, iteration)
          : malformedJwt(fuzzer);

      await expect(
        service.verifyToken(input),
        replay("JWT verification", iteration, input)
      ).resolves.toBeNull();
    }
  });

  test("never promotes a mutated or forged token through auth middleware", async () => {
    const fuzzer = createFuzzer(FUZZ_SEED ^ 0x41555448);
    const auth = new JWTService({ jwtSecret: JWT_SECRET });
    const admin = requireAdmin({ jwtSecret: JWT_SECRET });
    const validAdminToken = jwt.sign(
      { userId: "victim", role: "admin", sessionId: "known-session" },
      JWT_SECRET,
      { algorithm: "HS256", expiresIn: "1h" }
    );

    for (let iteration = 0; iteration < FUZZ_RUNS; iteration += 1) {
      const hostileToken =
        iteration % 2 === 0
          ? mutateCompactJwt(validAdminToken, fuzzer, iteration)
          : malformedJwt(fuzzer);
      const header = `Bearer ${hostileToken}`;
      const authResult = await invokeMiddleware(auth.authenticateJWT, header);
      const adminResult = await invokeMiddleware(admin, header);
      const message = replay("authorization middleware", iteration, header);

      expect(authResult.nextCalled, message).toBe(false);
      expect([401, 403], message).toContain(authResult.statusCode);
      expect(adminResult.nextCalled, message).toBe(false);
      expect([401, 403], message).toContain(adminResult.statusCode);
    }
  });

  test("fails closed for malformed IPs and spoofed proxy headers", async () => {
    const fuzzer = createFuzzer(FUZZ_SEED ^ 0x495053);
    const redis = fakeWhitelistRedis(["127.0.0.1", "203.0.113.9", "10.0.0.0/8"]);
    const security = new SecurityModule({
      redisClient: redis as never,
      rateLimiterEnabled: false,
      whiteListEnabled: true,
      trustProxyHeaders: false,
    });
    const middleware = security.whiteListMiddleware();

    for (let iteration = 0; iteration < FUZZ_RUNS; iteration += 1) {
      const malformedIp = `attacker:${fuzzer.text(1, 128)}`;
      const message = replay("IP whitelist", iteration, malformedIp);

      await expect(security.isAllowed(malformedIp), message).resolves.toBe(false);

      const req = {
        headers: {
          "x-forwarded-for": `203.0.113.9, ${fuzzer.text(1, 64)}`,
        },
        ip: `198.51.100.${1 + fuzzer.integer(253)}`,
        socket: {
          remoteAddress: `198.51.100.${1 + fuzzer.integer(253)}`,
        },
      } as unknown as Request;
      let nextCalled = false;
      let statusCode = 200;
      const res = {
        status(code: number) {
          statusCode = code;
          return this;
        },
        json() {
          return this;
        },
      } as unknown as Response;

      await middleware(req, res, () => {
        nextCalled = true;
      });

      expect(nextCalled, message).toBe(false);
      expect(statusCode, message).toBe(403);
    }
  });

  test("does not exchange guessed or corrupted OAuth state", async () => {
    const fuzzer = createFuzzer(FUZZ_SEED ^ 0x4f415554);
    const stateStore: OAuthStateStore = {
      async set() {},
      async get() {
        return null;
      },
      async del() {},
    };
    const google = createGoogleProvider(
      {
        clientId: "client",
        clientSecret: "secret",
        redirectUri: "https://sdk.test/oauth/google/callback",
      },
      stateStore
    );
    const github = createGitHubProvider(
      {
        clientId: "client",
        clientSecret: "secret",
        redirectUri: "https://sdk.test/oauth/github/callback",
      },
      stateStore
    );
    const fetchSpy = vi.fn();
    vi.stubGlobal("fetch", fetchSpy);

    for (let iteration = 0; iteration < FUZZ_RUNS; iteration += 1) {
      const state = fuzzer.text(1, 256);
      const code = fuzzer.text(1, 256);
      const req = { query: { state, code } } as unknown as Request;
      const message = replay("OAuth state", iteration, state);

      await expect(google.handleCallback(req), message).rejects.toThrow(
        "Invalid or expired state"
      );
      await expect(github.handleCallback(req), message).rejects.toThrow(
        "Invalid or expired state"
      );
    }

    expect(fetchSpy).not.toHaveBeenCalled();
  });
});
