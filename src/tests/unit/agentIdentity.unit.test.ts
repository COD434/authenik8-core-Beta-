import express from "express";
import request from "supertest";
import { beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import type { Mock } from "vitest";
import {
  AgentIdentityError,
  AgentIdentityService,
} from "../../agent/agentIdentity";
import type { RegisteredAgentIdentity } from "../../agent/types";
import type { AgentDelegationRequest } from "../../agent/types";
import { generateSigningJwk } from "../../auth/jwk";
import { JWTService } from "../../auth/jwtAuth";

class MemoryRedis {
  readonly hashes = new Map<string, Record<string, string>>();
  readonly values = new Map<string, string>();

  async hget(key: string, field: string) {
    return this.hashes.get(key)?.[field] ?? null;
  }

  async hgetall(key: string) {
    return this.hashes.get(key) ?? null;
  }

  async hset(key: string, field: string, value: string) {
    const hash = this.hashes.get(key) ?? {};
    hash[field] = value;
    this.hashes.set(key, hash);
    return 1;
  }

  async hdel(key: string, field: string) {
    const hash = this.hashes.get(key);
    if (hash) delete hash[field];
    return 1;
  }

  async expire(_key: string, _seconds: number) {
    return 1;
  }

  async set(key: string, value: string) {
    this.values.set(key, value);
    return "OK";
  }

  async exists(key: string) {
    return this.values.has(key) || this.hashes.has(key) ? 1 : 0;
  }

  async del(key: string) {
    this.values.delete(key);
    this.hashes.delete(key);
    return 1;
  }
}

describe("agent identity", () => {
  let signingKey: Awaited<ReturnType<typeof generateSigningJwk>>;
  let redis: MemoryRedis;
  let human: JWTService;
  let registry: Map<string, RegisteredAgentIdentity>;
  let authorizeDelegation: Mock<
    (request: AgentDelegationRequest) => Promise<boolean>
  >;
  let agents: AgentIdentityService;

  beforeAll(async () => {
    signingKey = await generateSigningJwk("agent-test-key");
  });

  beforeEach(() => {
    redis = new MemoryRedis();
    registry = new Map([
      [
        "worker-1",
        {
          agentId: "worker-1",
          scopes: ["tasks:read", "tasks:write"],
          active: true,
        },
      ],
    ]);
    authorizeDelegation = vi.fn(
      async (_request: AgentDelegationRequest) => true,
    );
    const jwk = {
      keys: [signingKey],
      activeKid: "agent-test-key",
      issuer: "https://issuer.example",
      audience: "example-api",
    };
    human = new JWTService({ jwk, redisClient: redis });
    agents = new AgentIdentityService({
      config: {
        resolveAgent: async (agentId) => registry.get(agentId) ?? null,
        authorizeDelegation,
      },
      redisClient: redis,
      jwk,
      issuer: jwk.issuer,
      audience: jwk.audience,
      verifyHumanToken: human.verifyActiveToken.bind(human),
      hasHumanSession: human.hasActiveSession.bind(human),
    });
  });

  it("issues scoped M2M tokens with an agent actor chain and session", async () => {
    const result = await agents.issueToken({
      agentId: "worker-1",
      scopes: ["tasks:read"],
      label: "queue worker",
      ip: "10.0.0.8",
    });
    const payload = await agents.verifyToken(result.accessToken);

    expect(result).toMatchObject({
      tokenUse: "agent",
      scopes: ["tasks:read"],
      sessionId: expect.any(String),
    });
    expect(payload).toMatchObject({
      sub: "agent:worker-1",
      agentId: "worker-1",
      scopes: ["tasks:read"],
      actorChain: [{ type: "agent", id: "worker-1" }],
    });
    expect(await human.verifyToken(result.accessToken)).toBeNull();
    await expect(agents.listSessions("worker-1")).resolves.toEqual([
      expect.objectContaining({
        sessionId: result.sessionId,
        label: "queue worker",
        ip: "10.0.0.8",
      }),
    ]);
  });

  it("rejects unknown agents, malformed scopes, and scope escalation", async () => {
    await expect(
      agents.issueToken({ agentId: "unknown", scopes: ["tasks:read"] }),
    ).rejects.toMatchObject({ code: "AGENT_INVALID" });
    await expect(
      agents.issueToken({ agentId: "worker-1", scopes: ["admin:all"] }),
    ).rejects.toMatchObject({ code: "AGENT_SCOPE_DENIED" });
    await expect(
      agents.issueToken({ agentId: "worker-1", scopes: ["Tasks Read"] }),
    ).rejects.toMatchObject({ code: "AGENT_SCOPE_DENIED" });
    await expect(
      agents.issueToken({
        agentId: "worker-1",
        scopes: [`tasks:${"r".repeat(123)}`],
      }),
    ).rejects.toMatchObject({ code: "AGENT_SCOPE_DENIED" });
  });

  it("invalidates existing tokens when registry grants are removed", async () => {
    const result = await agents.issueToken({
      agentId: "worker-1",
      scopes: ["tasks:write"],
    });
    registry.set("worker-1", {
      agentId: "worker-1",
      scopes: ["tasks:read"],
      active: true,
    });

    await expect(agents.verifyToken(result.accessToken)).resolves.toBeNull();
  });

  it("revokes one M2M session without revoking another", async () => {
    const first = await agents.issueToken({ agentId: "worker-1" });
    const second = await agents.issueToken({ agentId: "worker-1" });

    await agents.revokeSession("worker-1", first.sessionId);

    await expect(agents.verifyToken(first.accessToken)).resolves.toBeNull();
    await expect(agents.verifyToken(second.accessToken)).resolves.toMatchObject({
      sessionId: second.sessionId,
    });
  });

  it("revokes the whole agent until it is explicitly activated", async () => {
    const result = await agents.issueToken({ agentId: "worker-1" });
    await agents.revokeAgent("worker-1");

    await expect(agents.verifyToken(result.accessToken)).resolves.toBeNull();
    await expect(
      agents.issueToken({ agentId: "worker-1" }),
    ).rejects.toMatchObject({ code: "AGENT_REVOKED" });

    await agents.activateAgent("worker-1");
    await expect(agents.issueToken({ agentId: "worker-1" })).resolves.toMatchObject({
      tokenUse: "agent",
    });
  });

  it("issues delegated tokens with user and agent actors", async () => {
    const userAccessToken = await human.signToken({
      userId: "user-1",
      email: "user@example.com",
    });
    const result = await agents.issueDelegatedToken({
      agentId: "worker-1",
      userAccessToken,
      scopes: ["tasks:read"],
    });
    const payload = await agents.verifyToken(result.accessToken);

    expect(authorizeDelegation).toHaveBeenCalledWith(
      expect.objectContaining({
        agent: expect.objectContaining({ agentId: "worker-1" }),
        user: expect.objectContaining({ userId: "user-1" }),
        requestedScopes: ["tasks:read"],
      }),
    );
    expect(payload).toMatchObject({
      tokenUse: "agent-delegation",
      sub: "user:user-1",
      act: { sub: "agent:worker-1" },
      delegatedUserId: "user-1",
      actorChain: [
        { type: "user", id: "user-1" },
        { type: "agent", id: "worker-1" },
      ],
    });
  });

  it("invalidates delegated tokens when the human session is revoked", async () => {
    const userAccessToken = await human.signToken({ userId: "user-1" });
    const userPayload = await human.verifyToken(userAccessToken);
    const delegated = await agents.issueDelegatedToken({
      agentId: "worker-1",
      userAccessToken,
      scopes: ["tasks:read"],
    });

    await human.revokeSession("user-1", userPayload!.sessionId!);

    await expect(agents.verifyToken(delegated.accessToken)).resolves.toBeNull();
  });

  it("denies delegation when no application policy authorizes it", async () => {
    const userAccessToken = await human.signToken({ userId: "user-1" });
    const denied = new AgentIdentityService({
      config: { resolveAgent: async (agentId) => registry.get(agentId) ?? null },
      redisClient: redis,
      legacySecret: "agent-test-secret",
      issuer: "issuer",
      audience: "audience",
      verifyHumanToken: human.verifyActiveToken.bind(human),
      hasHumanSession: human.hasActiveSession.bind(human),
    });

    await expect(
      denied.issueDelegatedToken({
        agentId: "worker-1",
        userAccessToken,
        scopes: ["tasks:read"],
      }),
    ).rejects.toMatchObject({ code: "AGENT_DELEGATION_DENIED" });
  });

  it("enforces agent token type and every required route scope", async () => {
    const app = express();
    app.get(
      "/agent",
      agents.requireScopes("tasks:read", "tasks:write"),
      (req, res) => res.json({ agentId: (req as any).agent.agentId }),
    );
    const readOnly = await agents.issueToken({
      agentId: "worker-1",
      scopes: ["tasks:read"],
    });
    const readWrite = await agents.issueToken({ agentId: "worker-1" });
    const humanToken = await human.signToken({ userId: "user-1" });

    await request(app).get("/agent").expect(401);
    await request(app)
      .get("/agent")
      .set("Authorization", `Bearer ${humanToken}`)
      .expect(403);
    await request(app)
      .get("/agent")
      .set("Authorization", `Bearer ${readOnly.accessToken}`)
      .expect(403);
    await request(app)
      .get("/agent")
      .set("Authorization", `Bearer ${readWrite.accessToken}`)
      .expect(200, { agentId: "worker-1" });
  });

  it("fails fast without Redis session and revocation capabilities", () => {
    expect(
      () =>
        new AgentIdentityService({
          config: { resolveAgent: async () => null },
          redisClient: {},
          legacySecret: "agent-test-secret",
          issuer: "issuer",
          audience: "audience",
          verifyHumanToken: async () => null,
          hasHumanSession: async () => false,
        }),
    ).toThrow(AgentIdentityError);
  });
});
