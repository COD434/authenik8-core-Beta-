import express, { type NextFunction, type Request, type Response } from "express";
import request from "supertest";
import { beforeEach, describe, expect, it } from "vitest";
import { requireAdmin } from "../../middleware/adminService";

const redis = {
  hashes: new Map<string, Record<string, string>>(),
  async hgetall(key: string) {
    return this.hashes.get(key) ?? null;
  },
  async hdel(key: string, field: string) {
    delete this.hashes.get(key)?.[field];
  },
  async del(key: string) {
    this.hashes.delete(key);
  },
  seed(userId: string, sessionId: string, token = "never-return-this") {
    const key = `sessions:${userId}`;
    const hash = this.hashes.get(key) ?? {};
    hash[sessionId] = JSON.stringify({
      sessionId,
      device: "test",
      ip: "192.0.2.1",
      createdAt: Date.now(),
      token,
    });
    this.hashes.set(key, hash);
  },
};

const requireTestAuth = (
  req: Request,
  res: Response,
  next: NextFunction,
) => {
  const role = req.headers["x-test-authenticated-role"];
  if (typeof role !== "string") {
    return res.status(401).json({ error: "Unauthorized" });
  }
  (req as any).user = { role };
  return next();
};

const app = () => {
  const server = express();
  const admin = requireAdmin({
    requireAuth: requireTestAuth,
    store: redis,
  });
  server.get("/admin", admin, (_req, res) => res.json({ ok: true }));
  server.get("/sessions/:userId", admin, async (req, res) => {
    const actions = (req as any).adminActions;
    res.json({ sessions: await actions.listSessions(req.params.userId) });
  });
  server.delete("/sessions/:userId/:sessionId", admin, async (req, res) => {
    const actions = (req as any).adminActions;
    await actions.revokeSession(req.params.userId, req.params.sessionId);
    res.sendStatus(204);
  });
  return server;
};

describe("requireAdmin security contract", () => {
  beforeEach(() => redis.hashes.clear());

  it("does not grant access without upstream authentication", async () => {
    await request(app()).get("/admin").expect(401);
  });

  it("rejects spoofed non-admin and case-variant roles", async () => {
    await request(app())
      .get("/admin")
      .set("x-test-authenticated-role", "user")
      .expect(403);
    await request(app())
      .get("/admin")
      .set("x-test-authenticated-role", "Admin")
      .expect(403);
  });

  it("allows the exact role after upstream authentication", async () => {
    await request(app())
      .get("/admin")
      .set("x-test-authenticated-role", "admin")
      .expect(200, { ok: true });
  });

  it("lists session metadata without exposing bearer tokens", async () => {
    redis.seed("user-1", "session-1");
    const result = await request(app())
      .get("/sessions/user-1")
      .set("x-test-authenticated-role", "admin")
      .expect(200);

    expect(result.body.sessions).toEqual([
      expect.objectContaining({ sessionId: "session-1" }),
    ]);
    expect(result.body.sessions[0]).not.toHaveProperty("token");
  });

  it("revokes only the requested session", async () => {
    redis.seed("user-1", "session-1");
    redis.seed("user-1", "session-2");
    await request(app())
      .delete("/sessions/user-1/session-1")
      .set("x-test-authenticated-role", "admin")
      .expect(204);

    expect(Object.keys((await redis.hgetall("sessions:user-1"))!)).toEqual([
      "session-2",
    ]);
  });
});
