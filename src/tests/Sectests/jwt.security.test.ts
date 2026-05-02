import { JWTService } from "../../auth/jwtAuth";
import jwt from "jsonwebtoken";
import httpMocks from "node-mocks-http";
import { vi } from "vitest"

const SECRET = "test-secret";
const WRONG_SECRET = "wrong-secret";

// Mock Redis client
const mockRedis = {
  store: new Map <string,Record <string ,string>>(),
  async hgetall(key: string) {
    return this.store.get(key) ?? null;
  },

  async hset(key: string, field:string, value:string) {
	  const hash =this.store.get(key) ?? {};
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

const makeService = (withRedis = false) =>
  new JWTService({
    jwtSecret: SECRET,
    expiry: "1h",
    redisClient: withRedis ? mockRedis : undefined,
  });



describe("signToken", () => {
  it("produces a valid JWT",async () => {
    const svc = makeService();
    const token = await svc.signToken({ userId: "u1", email: "a@b.com" });
    const decoded = jwt.verify(token, SECRET) as any;
    expect(decoded.userId).toBe("u1");
  });

  it("defaults to 1h expiry when none supplied",async () => {
    const svc = new JWTService({ jwtSecret: SECRET });
    const token = await svc.signToken({ userId: "u1", email: "a@b.com" });
    const decoded = jwt.decode(token) as any;
    expect(decoded.exp - decoded.iat).toBeLessThanOrEqual(3600);
  });
});



describe("verifyToken — JWT attacks", () => {
  it("rejects a token signed with the wrong secret",async () => {
    const token =  jwt.sign({ userId: "u1", email: "a@b.com" }, WRONG_SECRET);
    expect(makeService().verifyToken(token)).toBeNull();
  });

  it("rejects an expired token", () => {
    const token  = jwt.sign(
      { userId: "u1", email: "a@b.com" },
      SECRET,
      { expiresIn: -1 } // already expired
    );
    expect(makeService().verifyToken(token)).toBeNull();
  });

  it("rejects a token with algorithm set to none (none-attack)", () => {
    // Craft a token with alg:none manually
    const header = Buffer.from(JSON.stringify({ alg: "none", typ: "JWT" }))
      .toString("base64url");
    const payload = Buffer.from(
      JSON.stringify({ userId: "u1", email: "a@b.com" })
    ).toString("base64url");
    const noneToken = `${header}.${payload}.`;
    expect(makeService().verifyToken(noneToken)).toBeNull();
  });

  it("rejects a tampered payload",async () => {
    const token = await  makeService().signToken({ userId: "u1", email: "a@b.com" });
    const [h, , sig] = token.split(".");
    const tampered = Buffer.from(
      JSON.stringify({ userId: "admin", email: "evil@b.com" })
    ).toString("base64url");
    const tamperedToken = `${h}.${tampered}.${sig}`;
    expect(makeService().verifyToken(tamperedToken)).toBeNull();
  });

  it("returns null for a completely invalid string", () => {
    expect(makeService().verifyToken("not.a.token")).toBeNull();
  });
});

// ─── guestToken ───────────────────────────────────────────────────────────────

describe("guestToken", () => {
  it("produces a token with type guest", () => {
    const token =  makeService().guestToken();
    const decoded = jwt.verify(token, SECRET) as any;
    expect(decoded.type).toBe("guest");
  });

  it("each guest token has a unique id", () => {
    const svc = makeService();
    const t1 = jwt.decode(svc.guestToken()) as any;
    const t2 = jwt.decode(svc.guestToken()) as any;
    expect(t1.id).not.toBe(t2.id);
  });

  it("fires onGuestToken callback", () => {
    const cb = vi.fn();
    const svc = new JWTService({ jwtSecret: SECRET,expiry: "1h", onGuestToken: cb });
    svc.guestToken();
    expect(cb).toHaveBeenCalledTimes(1);
  });
});

// ─── authenticateJWT middleware ───────────────────────────────────────────────

describe("authenticateJWT — middleware", () => {
  beforeEach(() => mockRedis.clear());

  const run = async (
    svc: JWTService,
    token: string | null,
    via: "bearer" | "cookie" = "bearer"
  ) => {
    const req = httpMocks.createRequest({
      headers:
        via === "bearer" && token
          ? { authorization: `Bearer ${token}` }
          : {},
      cookies: via === "cookie" && token ? { token } : {},
    });
    const res = httpMocks.createResponse();
    const next = vi.fn();
    await svc.authenticateJWT(req, res, next);
    return { req, res, next };
  };

  it("calls next() for a valid Bearer token", async () => {
    const svc = makeService();
    const token = await svc.signToken({ userId: "u1", email: "a@b.com" });
    const { next } = await run(svc, token);
    expect(next).toHaveBeenCalled();
  });

  it("calls next() for a valid cookie token", async () => {
    const svc = makeService();
    const token = await svc.signToken({ userId: "u1", email: "a@b.com" });
    const { next } = await run(svc, token, "cookie");
    expect(next).toHaveBeenCalled();
  });

  it("returns 401 when no token is present", async () => {
    const { res, next } = await run(makeService(), null);
    expect(res.statusCode).toBe(401);
    expect(next).not.toHaveBeenCalled();
  });

  it("returns 403 for an expired token", async () => {
    const token = jwt.sign({ userId: "u1", email: "a@b.com" }, SECRET, {
      expiresIn: -1,
    });
    const { res, next } = await run(makeService(), token);
    expect(res.statusCode).toBe(403);
    expect(next).not.toHaveBeenCalled();
  });

  it("returns 403 for a token signed with wrong secret", async () => {
    const token = jwt.sign({ userId: "u1", email: "a@b.com" }, WRONG_SECRET);
    const { res, next } = await run(makeService(), token);
    expect(res.statusCode).toBe(403);
    expect(next).not.toHaveBeenCalled();
  });

  // Redis session validation
  it("returns 403 when token does not match stored session (stolen token)", async () => {
    const svc = makeService(true);
    const realToken = await svc.signToken({ userId: "u1", email: "a@b.com" });
    await new Promise((r) => setTimeout(r, 20))
    const stolenToken = jwt.sign({ userId: "u1", email: "a@b.com" }, SECRET, {
      expiresIn: "1h",
    });
    
    const { res, next } = await run(svc, stolenToken);
    expect(res.statusCode).toBe(403);
    expect(next).not.toHaveBeenCalled();
  });

  it("calls next() when token matches stored session exactly", async () => {
    const svc = makeService(true);
    const token = await svc.signToken({ userId: "u1", email: "a@b.com" });

   const {next} =await run( svc, token);          
   expect(next).toHaveBeenCalled();      
  });

  it("attaches decoded user to req after successful auth", async () => {
    const svc = makeService();
    const token = await svc.signToken({ userId: "u1", email: "a@b.com" });
    const { req } = await run(svc, token);
    expect((req as any).user.userId).toBe("u1");
  });
});

