import express from "express";
import request from "supertest";
import jwt from "jsonwebtoken";
import { requireAdmin } from "../../middleware/adminService";

describe("requireAdmin", () => {
  const jwtSecret = "admin-unit-secret";

  const createApp = () => {
    const app = express();

    app.get(
      "/admin",
      requireAdmin({ jwtSecret }),
      (_req, res) => res.status(200).json({ ok: true })
    );

    return app;
  };

  test("rejects requests without a token", async () => {
    const response = await request(createApp()).get("/admin");

    expect(response.status).toBe(401);
  });

  test("rejects non-admin roles", async () => {
    const token = jwt.sign({ id: "user-1", role: "user" }, jwtSecret);
    const response = await request(createApp())
      .get("/admin")
      .set("Authorization", `Bearer ${token}`);

    expect(response.status).toBe(403);
  });

  test("rejects tokens without an admin role", async () => {
    const token = jwt.sign({ id: "user-1" }, jwtSecret);
    const response = await request(createApp())
      .get("/admin")
      .set("Authorization", `Bearer ${token}`);

    expect(response.status).toBe(403);
  });

  test("allows admin tokens", async () => {
    const token = jwt.sign({ id: "admin-1", role: "admin" }, jwtSecret);
    const response = await request(createApp())
      .get("/admin")
      .set("Authorization", `Bearer ${token}`);

    expect(response.status).toBe(200);
    expect(response.body).toEqual({ ok: true });
  });
});
