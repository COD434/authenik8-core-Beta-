import express, { Request, Response } from "express";
import request from "supertest";
import jwt from "jsonwebtoken";
import { requireAdmin } from "../../middleware/adminService";

const jwtSecret = "admin-unit-secret";



const mockRedis = {
  store: new Map<string, Record<string, string>>(),

  async hset(key: string, field: string, value: string) {
    if (!this.store.has(key)) this.store.set(key, {});
    this.store.get(key)![field] = value;
  },

  async hgetall(key: string) {
    return this.store.get(key) ?? null;
  },

  async hdel(key: string, field: string) {
    const hash = this.store.get(key) 
    if(hash) delete this.store.get(key)![field];
  },

  async del(key: string) {
    this.store.delete(key);
  },

  async expire(_key: string, _ttl: number) {},

  clear() {
    this.store.clear();
  },

  async seedSession(userId: string, sessionId: string, meta: object, token: string) {
    if (!this.store.has(`sessions:${userId}`)) this.store.set(`sessions:${userId}`, {});
    this.store.get(`sessions:${userId}`)![sessionId] = JSON.stringify({ token, ...meta });
  },
};



const createApp = () => {
  const app = express();
   app.get("/admin", requireAdmin({ jwtSecret }), (_req, res) =>
    res.status(200).json({ ok: true })
  );
  return app;
};

const createAppWithRedis = () => {
  const app = express();
  app.use(express.json());
 app.use((req, _res, next) => {
    const cookieHeader = req.headers.cookie;
    if (cookieHeader) {
      req.cookies = Object.fromEntries(
        cookieHeader.split(";").map((c) => {
          const [key, ...val] = c.trim().split("=");
          return [key, val.join("=")];
        })
      );
    }
    next();
  });

  app.get("/admin", requireAdmin({ jwtSecret, store: mockRedis }), (_req, res) =>
    res.status(200).json({ ok: true })
  );

  app.get(
    "/admin/sessions/:userId",
    requireAdmin({ jwtSecret, store: mockRedis }),
    async (req: Request, res: Response) => {
      const sessions = await (req as any).adminActions.listSessions(req.params.userId);
      res.status(200).json({ sessions });
    }
  );

  app.delete(
    "/admin/sessions/:userId/:sessionId",
    requireAdmin({ jwtSecret, store: mockRedis }),
    async (req: Request, res: Response) => {
      await (req as any).adminActions.revokeSession(req.params.userId, req.params.sessionId);
      res.status(200).json({ ok: true });
    }
  );

  app.delete(
    "/admin/sessions/:userId",
    requireAdmin({ jwtSecret, store: mockRedis }),
    async (req: Request, res: Response) => {
      await (req as any).adminActions.revokeAllSessions(req.params.userId);
      res.status(200).json({ ok: true });
    }
  );

  return app;
};



const adminToken = () => jwt.sign({ userId: "admin-1", role: "admin" }, jwtSecret);
const userToken = () => jwt.sign({ userId: "user-1", role: "user" }, jwtSecret);


describe("requireAdmin", () => {
  test("rejects requests without a token", async () => {
    const response = await request(createAppWithRedis()).get("/admin");
    expect(response.status).toBe(401);
  });

  test("rejects non-admin roles", async () => {
    const response = await request(createApp())
      .get("/admin")
      .set("Authorization", `Bearer ${userToken()}`);
    expect(response.status).toBe(403);
  });

  test("rejects tokens without a role", async () => {
    const token = jwt.sign({ userId: "user-1" }, jwtSecret);
    const response = await request(createApp())
      .get("/admin")
      .set("Authorization", `Bearer ${token}`);
    expect(response.status).toBe(403);
  });

  test("rejects tokens with wrong secret", async () => {
    const token = jwt.sign({ userId: "admin-1", role: "admin" }, "wrong-secret");
    const response = await request(createAppWithRedis())
      .get("/admin")
      .set("Authorization", `Bearer ${token}`);
    expect(response.status).toBe(401);
  });

  test("rejects expired tokens", async () => {
    const token = jwt.sign({ userId: "admin-1", role: "admin" }, jwtSecret, { expiresIn: -1 });
    const response = await request(createAppWithRedis())
      .get("/admin")
      .set("Authorization", `Bearer ${token}`);
    expect(response.status).toBe(401);
  });

  test("rejects role casing variations like Admin", async () => {
    const token = jwt.sign({ userId: "admin-1", role: "Admin" }, jwtSecret);
    const response = await request(createApp())
      .get("/admin")
      .set("Authorization", `Bearer ${token}`);
    expect(response.status).toBe(403);
  });

  test("allows admin tokens via Bearer header", async () => {
    const response = await request(createAppWithRedis())
      .get("/admin")
      .set("Authorization", `Bearer ${adminToken()}`);
    expect(response.status).toBe(200);
    expect(response.body).toEqual({ ok: true });
  });

  test("allows admin tokens via cookie", async () => {
    const response = await request(createAppWithRedis())
      .get("/admin")
      .set("Cookie", `token=${adminToken()}`);
    expect(response.status).toBe(200);
  });
});



describe("requireAdmin — adminActions", () => {
  beforeEach(() => mockRedis.clear());

  test("non-admin cannot access listSessions", async () => {
    const response = await request(createAppWithRedis())
      .get("/admin/sessions/u1")
      .set("Authorization", `Bearer ${userToken()}`);
    expect(response.status).toBe(403);
  });

  test("listSessions returns all sessions without exposing tokens", async () => {
    await mockRedis.seedSession("u1", "s1", { device: "Chrome/Mac", ip: "41.1.1.1", sessionId: "s1", createdAt: Date.now() }, "token-abc");
    await mockRedis.seedSession("u1", "s2", { device: "Safari/iPhone", ip: "41.2.2.2", sessionId: "s2", createdAt: Date.now() }, "token-xyz");

    const response = await request(createAppWithRedis())
      .get("/admin/sessions/u1")
      .set("Authorization", `Bearer ${adminToken()}`);

    expect(response.status).toBe(200);
    expect(response.body.sessions.length).toBe(2);
    response.body.sessions.forEach((s: any) => {
      expect(s.token).toBeUndefined();
      expect(s.device).toBeDefined();
      expect(s.ip).toBeDefined();
      expect(s.sessionId).toBeDefined();
    });
  });

  test("listSessions returns empty array for user with no sessions", async () => {
    const response = await request(createAppWithRedis())
      .get("/admin/sessions/ghost")
      .set("Authorization", `Bearer ${adminToken()}`);
    expect(response.status).toBe(200);
    expect(response.body.sessions.length).toBe(0);
  });

  test("revokeSession removes only the targeted session", async () => {
    await mockRedis.seedSession("u1", "s1", { device: "Chrome/Mac", ip: "41.1.1.1", sessionId: "s1", createdAt: Date.now() }, "token-abc");
    await mockRedis.seedSession("u1", "s2", { device: "Safari/iPhone", ip: "41.2.2.2", sessionId: "s2", createdAt: Date.now() }, "token-xyz");

    const response = await request(createAppWithRedis())
      .delete("/admin/sessions/u1/s2")
      .set("Authorization", `Bearer ${adminToken()}`);

    expect(response.status).toBe(200);
    const remaining = await mockRedis.hgetall("sessions:u1");
    expect(Object.keys(remaining!)).toContain("s1");
    expect(Object.keys(remaining!)).not.toContain("s2");
  });

  test("revokeSession does not affect other users", async () => {
    await mockRedis.seedSession("u1", "s1", { device: "Chrome/Mac", ip: "41.1.1.1", sessionId: "s1", createdAt: Date.now() }, "token-abc");
    await mockRedis.seedSession("u2", "s2", { device: "Firefox/Win", ip: "41.3.3.3", sessionId: "s2", createdAt: Date.now() }, "token-def");

    await request(createAppWithRedis())
      .delete("/admin/sessions/u1/s1")
      .set("Authorization", `Bearer ${adminToken()}`);

    const u2Sessions = await mockRedis.hgetall("sessions:u2");
    expect(Object.keys(u2Sessions!)).toContain("s2");
  });

  test("revokeAllSessions removes all sessions for a user", async () => {
    await mockRedis.seedSession("u1", "s1", { device: "Chrome/Mac", ip: "41.1.1.1", sessionId: "s1", createdAt: Date.now() }, "token-abc");
    await mockRedis.seedSession("u1", "s2", { device: "Safari/iPhone", ip: "41.2.2.2", sessionId: "s2", createdAt: Date.now() }, "token-xyz");

	const response = await request(createAppWithRedis()).delete("/admin/sessions/u1").set("Authorization", `Bearer ${adminToken()}`);
	    expect(response.status).toBe(200);
	    const remaining = await mockRedis.hgetall("sessions:u1");
	    expect(remaining).toBeNull();
	  });

  test("revokeAllSessions does not affect other users", async () => {
    await mockRedis.seedSession("u1", "s1", { device: "Chrome/Mac", ip: "41.1.1.1", sessionId: "s1", createdAt: Date.now() }, "token-abc");
    await mockRedis.seedSession("u2", "s2", { device: "Firefox/Win", ip: "41.3.3.3", sessionId: "s2", createdAt: Date.now() }, "token-def");

    await request(createAppWithRedis())
      .delete("/admin/sessions/u1")
      .set("Authorization", `Bearer ${adminToken()}`);

    const u2Sessions = await mockRedis.hgetall("sessions:u2");
    expect(Object.keys(u2Sessions!)).toContain("s2");
  });
});
