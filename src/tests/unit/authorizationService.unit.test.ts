import httpMocks from "node-mocks-http";
import { describe, expect, it, vi } from "vitest";
import { AuthorizationService } from "../../authorization/authorizationService";
import type { JwtPayload } from "../../auth/jwtAuth";
import { markAuthenik8Authenticated } from "../../auth/requestIdentity";

const invoke = async (
  authorization: AuthorizationService,
  middleware: ReturnType<AuthorizationService["requireRole"]>,
  requestOptions: Parameters<typeof httpMocks.createRequest>[0] = {},
) => {
  const request = httpMocks.createRequest(requestOptions);
  const response = httpMocks.createResponse();
  const next = vi.fn();
  await middleware(request, response, next);
  return { request, response, next };
};

const serviceFor = (
  user: JwtPayload,
  options: ConstructorParameters<typeof AuthorizationService>[0] = {
    authenticate: vi.fn(),
  },
) =>
  new AuthorizationService({
    ...options,
    authenticate: (request, _response, next) => {
      (request as any).user = user;
      next();
    },
  });

describe("AuthorizationService", () => {
  it("accepts any required role using exact, case-sensitive matching", async () => {
    const authorization = serviceFor({
      userId: "user-1",
      role: "member",
      roles: ["billing-admin"],
    });

    expect(
      (
        await invoke(
          authorization,
          authorization.requireRole("owner", "billing-admin"),
        )
      ).next,
    ).toHaveBeenCalledOnce();
    expect(
      (
        await invoke(
          authorization,
          authorization.requireRole("Billing-Admin"),
        )
      ).response.statusCode,
    ).toBe(403);
  });

  it("requires every requested permission and scope in linear set lookups", async () => {
    const authorization = serviceFor({
      userId: "user-1",
      permissions: ["invoice:read", "invoice:write"],
      scopes: ["profile:read"],
      scope: "email:read account:read",
    });

    expect(
      (
        await invoke(
          authorization,
          authorization.requirePermission("invoice:read", "invoice:write"),
        )
      ).next,
    ).toHaveBeenCalledOnce();
    expect(
      (
        await invoke(
          authorization,
          authorization.requireScope("profile:read", "email:read"),
        )
      ).next,
    ).toHaveBeenCalledOnce();
    expect(
      (
        await invoke(
          authorization,
          authorization.requirePermission("invoice:delete"),
        )
      ).response.statusCode,
    ).toBe(403);
  });

  it("fails closed when configured tenant context is missing or mismatched", async () => {
    const authorization = serviceFor(
      { userId: "user-1", role: "admin", tenantIds: ["tenant-a"] },
      {
        authenticate: vi.fn(),
        config: {
          resolveTenant: (request) => {
            const value = request.params.tenantId;
            return typeof value === "string" ? value : undefined;
          },
        },
      },
    );

    expect(
      (
        await invoke(
          authorization,
          authorization.requireRole("admin"),
          { params: { tenantId: "tenant-a" } },
        )
      ).next,
    ).toHaveBeenCalledOnce();
    expect(
      (
        await invoke(
          authorization,
          authorization.requireRole("admin"),
          { params: { tenantId: "tenant-b" } },
        )
      ).response.statusCode,
    ).toBe(403);
    expect(
      (
        await invoke(authorization, authorization.requireRole("admin"))
      ).response.statusCode,
    ).toBe(403);
  });

  it("emits a structured denial without exposing granted claims", async () => {
    const audit = { emit: vi.fn().mockResolvedValue(undefined) };
    const authorization = serviceFor(
      { userId: "user-1", sessionId: "session-1", role: "member" },
      { authenticate: vi.fn(), audit },
    );

    const result = await invoke(
      authorization,
      authorization.requireRole("admin"),
      { headers: { "x-request-id": "request-1" } },
    );

    expect(result.response.statusCode).toBe(403);
    expect(audit.emit).toHaveBeenCalledWith(
      expect.objectContaining({
        type: "authorization.denied",
        actor: { type: "user", id: "user-1" },
        sessionId: "session-1",
        correlationId: "request-1",
        metadata: { kind: "role", required: ["admin"] },
      }),
    );
  });

  it("rejects empty or unbounded requirements at startup", () => {
    const authorization = serviceFor({ userId: "user-1" });
    expect(() => authorization.requireRole()).toThrow("requireRole");
    expect(() =>
      authorization.requireScope(...Array.from({ length: 65 }, (_, i) => `s:${i}`)),
    ).toThrow("requireScope");
  });

  it("authenticates once when multiple SDK authorization checks are composed", async () => {
    const authenticate = vi.fn((request, _response, next) => {
      (request as any).user = {
        userId: "user-1",
        role: "admin",
        permissions: ["users:read"],
      };
      markAuthenik8Authenticated(request);
      next();
    });
    const authorization = new AuthorizationService({ authenticate });
    const request = httpMocks.createRequest();
    const response = httpMocks.createResponse();

    await authorization.requireRole("admin")(request, response, vi.fn());
    await authorization.requirePermission("users:read")(
      request,
      response,
      vi.fn(),
    );

    expect(authenticate).toHaveBeenCalledOnce();
  });
});
