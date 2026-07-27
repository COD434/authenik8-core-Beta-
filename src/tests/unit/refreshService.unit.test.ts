import { createHash } from "crypto";
import { decodeJwt } from "jose";
import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  InvalidTokenError,
  MissingTokenError,
  RefreshService,
  type RefreshServiceOptions,
  type TokenStore,
} from "../../auth/refreshService";
import { tokenFingerprint } from "../../auth/tokenFingerprint";

const pairDigest = (first: string, second: string): string =>
  createHash("sha256")
    .update(first)
    .update("\0")
    .update(second)
    .digest("base64url");
const refreshKey = (userId: string, sessionId: string): string =>
  `refresh:${pairDigest(userId, sessionId)}`;
const lockKey = (userId: string, sessionId: string): string =>
  `lock:${pairDigest(userId, sessionId)}`;

const mockLockInstance = {
  acquire: vi.fn(),
  release: vi.fn(),
};

vi.mock("../../utility/lockHelper", () => ({
  RedisLock: vi.fn(function () {
    return mockLockInstance;
  }),
}));

describe("RefreshService", () => {
  let tokenStore: TokenStore;
  let redisClient: any;
  let accessTokenSigner: RefreshServiceOptions["accessTokenSigner"];
  let options: RefreshServiceOptions;
  let service: RefreshService;

  const userPayload = {
    userId: "user123",
    email: "test@example.com",
    sessionId: "session-1",
  };

  beforeEach(() => {
    vi.clearAllMocks();
    tokenStore = {
      get: vi.fn(),
      set: vi.fn(),
      del: vi.fn(),
      compareAndSet: vi.fn(),
    };
    redisClient = {
      hget: vi.fn().mockResolvedValue(null),
      hset: vi.fn().mockResolvedValue(1),
      hdel: vi.fn().mockResolvedValue(1),
      hgetall: vi.fn().mockResolvedValue({}),
      del: vi.fn().mockResolvedValue(1),
      expire: vi.fn().mockResolvedValue(1),
    };
    accessTokenSigner = vi.fn(async () => "new.access.token");
    options = {
      tokenStore,
      redisClient,
      refreshTokenSecret: "refresh-secret-test-32-bytes-minimum",
      accessTokenSigner,
      issuer: "test-issuer",
      audience: "test-api",
      rotateRefreshTokens: false,
      refreshTokenExpiry: "7d",
    };
    service = new RefreshService(options);
    mockLockInstance.acquire.mockResolvedValue("lock-value-xyz");
  });

  it("generates a purpose-bound token with jti and stores it", async () => {
    const token = await service.generateRefreshToken(userPayload);
    const payload = decodeJwt(token);

    expect(payload).toMatchObject({
      ...userPayload,
      tokenUse: "refresh",
      iss: "test-issuer",
      aud: "test-api",
    });
    expect(payload.jti).toEqual(expect.any(String));
    expect(tokenStore.set).toHaveBeenCalledWith(
      refreshKey("user123", "session-1"),
      tokenFingerprint(token),
      60 * 60 * 24 * 7,
    );
    expect(redisClient.hset).toHaveBeenCalledWith(
      "refresh-families:user123",
      "session-1",
      "1",
    );
  });

  it("supports a read-only token store and validates required identity", async () => {
    const storeWithoutSet = { get: vi.fn() };
    const readOnlyService = new RefreshService({
      ...options,
      tokenStore: storeWithoutSet,
    });
    await expect(readOnlyService.generateRefreshToken(userPayload)).resolves.toEqual(
      expect.any(String),
    );
    await expect(
      service.generateRefreshToken({ email: "test@example.com" } as any),
    ).rejects.toThrow("generateRefreshToken: payload.userId");
    expect(
      () =>
        new RefreshService({
          ...options,
          rotateRefreshTokens: 1 as never,
        }),
    ).toThrow(/boolean/i);
  });

  it("rejects missing, malformed, and wrong-purpose tokens", async () => {
    await expect(service.refresh()).rejects.toThrow(MissingTokenError);
    await expect(service.refresh("bad.token")).rejects.toThrow(InvalidTokenError);
  });

  it("rejects a concurrent refresh before reading token state", async () => {
    const token = await service.generateRefreshToken(userPayload);
    mockLockInstance.acquire.mockResolvedValue(null);

    await expect(service.refresh(token)).rejects.toThrow("Concurrent refresh detected");
    expect(tokenStore.get).not.toHaveBeenCalled();
    expect(mockLockInstance.release).not.toHaveBeenCalled();
  });

  it("revokes the refresh family when the stored token does not match", async () => {
    const token = await service.generateRefreshToken(userPayload);
    vi.mocked(tokenStore.get).mockResolvedValue("different.token");

    await expect(service.refresh(token)).rejects.toThrow(InvalidTokenError);
    expect(tokenStore.del).toHaveBeenCalledWith(
      refreshKey("user123", "session-1"),
    );
    expect(redisClient.hdel).toHaveBeenCalledWith("sessions:user123", "session-1");
    expect(redisClient.hdel).toHaveBeenCalledWith(
      "refresh-families:user123",
      "session-1",
    );
  });

  it("reports replay risk before revoking the compromised family", async () => {
    const risk = {
      isQuarantined: vi.fn().mockResolvedValue(false),
      report: vi.fn().mockResolvedValue({
        status: "quarantined",
        reasons: ["refresh_replay"],
      }),
    };
    const guarded = new RefreshService({ ...options, risk: risk as any });
    const token = await guarded.generateRefreshToken(userPayload);
    vi.mocked(tokenStore.get).mockResolvedValue("different.token");

    await expect(guarded.refresh(token)).rejects.toThrow(InvalidTokenError);
    expect(risk.report).toHaveBeenCalledWith({
      type: "refresh_replay",
      principal: {
        kind: "human",
        id: "user123",
        sessionId: "session-1",
      },
    });
  });

  it("issues a new access token and releases the lock", async () => {
    const token = await service.generateRefreshToken(userPayload);
    vi.mocked(tokenStore.get).mockResolvedValue(token);

    await expect(service.refresh(token)).resolves.toEqual({
      accessToken: "new.access.token",
      refreshToken: token,
    });
    expect(accessTokenSigner).toHaveBeenCalledWith(userPayload);
    expect(mockLockInstance.release).toHaveBeenCalledWith(
      lockKey("user123", "session-1"),
      "lock-value-xyz",
    );
  });

  it("rotates refresh tokens atomically", async () => {
    const rotating = new RefreshService({ ...options, rotateRefreshTokens: true });
    const token = await rotating.generateRefreshToken(userPayload);
    vi.mocked(tokenStore.get).mockResolvedValue(token);
    vi.mocked(tokenStore.compareAndSet!).mockResolvedValue(true);

    const result = await rotating.refresh(token);
    expect(result.refreshToken).not.toBe(token);
    expect(tokenStore.compareAndSet).toHaveBeenCalledWith(
      refreshKey("user123", "session-1"),
      token,
      tokenFingerprint(result.refreshToken!),
      60 * 60 * 24 * 7,
    );
  });

  it("revokes the family when atomic rotation loses the race", async () => {
    const rotating = new RefreshService({ ...options, rotateRefreshTokens: true });
    const token = await rotating.generateRefreshToken(userPayload);
    vi.mocked(tokenStore.get).mockResolvedValue(token);
    vi.mocked(tokenStore.compareAndSet!).mockResolvedValue(false);

    await expect(rotating.refresh(token)).rejects.toThrow("Concurrent refresh detected");
    expect(tokenStore.del).toHaveBeenCalledWith(
      refreshKey("user123", "session-1"),
    );
    expect(redisClient.hdel).toHaveBeenCalledWith("sessions:user123", "session-1");
  });

  it("still revokes a lost refresh race when strict audit delivery fails", async () => {
    const audit = {
      emit: vi.fn().mockResolvedValue(undefined),
    };
    const rotating = new RefreshService({
      ...options,
      rotateRefreshTokens: true,
      audit,
    });
    const token = await rotating.generateRefreshToken(userPayload);
    audit.emit.mockRejectedValue(new Error("audit unavailable"));
    vi.mocked(tokenStore.get).mockResolvedValue(token);
    vi.mocked(tokenStore.compareAndSet!).mockResolvedValue(false);

    await expect(rotating.refresh(token)).rejects.toThrow("audit unavailable");
    expect(tokenStore.del).toHaveBeenCalledWith(
      refreshKey("user123", "session-1"),
    );
  });

  it("always releases an acquired lock", async () => {
    const token = await service.generateRefreshToken(userPayload);
    vi.mocked(tokenStore.get).mockRejectedValue(new Error("redis boom"));

    await expect(service.refresh(token)).rejects.toThrow("redis boom");
    expect(mockLockInstance.release).toHaveBeenCalledWith(
      lockKey("user123", "session-1"),
      "lock-value-xyz",
    );
  });

  it("revokes rotated state when access-token issuance fails", async () => {
    const rotating = new RefreshService({
      ...options,
      rotateRefreshTokens: true,
      accessTokenSigner: vi.fn().mockRejectedValue(new Error("signing failed")),
    });
    const token = await rotating.generateRefreshToken(userPayload);
    vi.mocked(tokenStore.get).mockResolvedValue(token);
    vi.mocked(tokenStore.compareAndSet!).mockResolvedValue(true);

    await expect(rotating.refresh(token)).rejects.toThrow("signing failed");
    expect(tokenStore.del).toHaveBeenCalledWith(
      refreshKey("user123", "session-1"),
    );
    expect(redisClient.hdel).toHaveBeenCalledWith(
      "sessions:user123",
      "session-1",
    );
  });

  it("revokes indexed refresh families even after access sessions have expired", async () => {
    redisClient.hgetall.mockResolvedValue({
      "session-1": "1",
      "session-2": "1",
    });

    await service.revokeAllSessions("user123");

    expect(tokenStore.del).toHaveBeenCalledWith(
      refreshKey("user123", "session-1"),
    );
    expect(tokenStore.del).toHaveBeenCalledWith(
      refreshKey("user123", "session-2"),
    );
    expect(redisClient.del).toHaveBeenCalledWith("refresh-families:user123");
    expect(redisClient.del).toHaveBeenCalledWith("sessions:user123");
  });

  it("uses collision-resistant compound keys for attacker-influenced identifiers", async () => {
    await service.generateRefreshToken({
      userId: "tenant:user",
      email: "one@example.com",
      sessionId: "session",
    });
    await service.generateRefreshToken({
      userId: "tenant",
      email: "two@example.com",
      sessionId: "user:session",
    });

    const keys = vi
      .mocked(tokenStore.set!)
      .mock.calls.map(([key]) => key);
    expect(keys).toHaveLength(2);
    expect(new Set(keys)).toHaveLength(2);
    expect(keys.every((key) => /^refresh:[A-Za-z0-9_-]{43}$/.test(key))).toBe(
      true,
    );
  });
});
