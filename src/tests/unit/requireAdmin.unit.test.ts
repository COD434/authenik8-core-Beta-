import type { NextFunction, Request, Response } from "express";
import { describe, expect, it, vi } from "vitest";
import { requireAdmin } from "../../middleware/adminService";

const response = () =>
  ({
    status: vi.fn().mockReturnThis(),
    json: vi.fn().mockReturnThis(),
  }) as unknown as Response;

const authenticateAs =
  (role?: string) =>
  (req: Request, _res: Response, next: NextFunction) => {
    (req as any).user = { role };
    next();
  };

describe("requireAdmin", () => {
  it("requires an explicitly supplied session-aware authenticator", () => {
    expect(() => requireAdmin({} as never)).toThrow(/session-aware requireAuth/);
  });

  it("preserves an upstream authentication denial", async () => {
    const res = response();
    const next: NextFunction = vi.fn();
    const middleware = requireAdmin({
      requireAuth: (_req, denied, _next) =>
        denied.status(401).json({ error: "Unauthorized" }),
    });

    await middleware({} as Request, res, next);
    expect(res.status).toHaveBeenCalledWith(401);
    expect(next).not.toHaveBeenCalled();
  });

  it("requires the exact lower-case admin role", async () => {
    for (const role of [undefined, "user", "Admin"]) {
      const res = response();
      const next: NextFunction = vi.fn();
      await requireAdmin({ requireAuth: authenticateAs(role) })(
        {} as Request,
        res,
        next,
      );
      expect(res.status).toHaveBeenCalledWith(403);
      expect(next).not.toHaveBeenCalled();
    }
  });

  it("allows an authenticated exact admin role", async () => {
    const next: NextFunction = vi.fn();
    await requireAdmin({ requireAuth: authenticateAs("admin") })(
      {} as Request,
      response(),
      next,
    );
    expect(next).toHaveBeenCalledOnce();
  });
});
