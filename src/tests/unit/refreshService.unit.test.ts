import { decodeJwt } from "jose";
import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  InvalidTokenError,
  MissingTokenError,
  RefreshService,
  type RefreshServiceOptions,
  type TokenStore,
} from "../../auth/refreshService";

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
      refreshTokenSecret: "refresh-secret-test",
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
      "refresh:user123:session-1",
      token,
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
    ).rejects.toThrow("generateRefreshToken: payload.userId is missing");
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
    expect(tokenStore.del).toHaveBeenCalledWith("refresh:user123:session-1");
    expect(redisClient.hdel).toHaveBeenCalledWith("sessions:user123", "session-1");
    expect(redisClient.hdel).toHaveBeenCalledWith(
      "refresh-families:user123",
      "session-1",
    );
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
      "lock:user123:session-1",
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
      "refresh:user123:session-1",
      token,
      result.refreshToken,
      60 * 60 * 24 * 7,
    );
  });

  it("revokes the family when atomic rotation loses the race", async () => {
    const rotating = new RefreshService({ ...options, rotateRefreshTokens: true });
    const token = await rotating.generateRefreshToken(userPayload);
    vi.mocked(tokenStore.get).mockResolvedValue(token);
    vi.mocked(tokenStore.compareAndSet!).mockResolvedValue(false);

    await expect(rotating.refresh(token)).rejects.toThrow("Concurrent refresh detected");
    expect(tokenStore.del).toHaveBeenCalledWith("refresh:user123:session-1");
    expect(redisClient.hdel).toHaveBeenCalledWith("sessions:user123", "session-1");
  });

  it("always releases an acquired lock", async () => {
    const token = await service.generateRefreshToken(userPayload);
    vi.mocked(tokenStore.get).mockRejectedValue(new Error("redis boom"));

    await expect(service.refresh(token)).rejects.toThrow("redis boom");
    expect(mockLockInstance.release).toHaveBeenCalledWith(
      "lock:user123:session-1",
      "lock-value-xyz",
    );
  });

  it("revokes indexed refresh families even after access sessions have expired", async () => {
    redisClient.hgetall.mockResolvedValue({
      "session-1": "1",
      "session-2": "1",
    });

    await service.revokeAllSessions("user123");

    expect(tokenStore.del).toHaveBeenCalledWith("refresh:user123:session-1");
    expect(tokenStore.del).toHaveBeenCalledWith("refresh:user123:session-2");
    expect(redisClient.del).toHaveBeenCalledWith("refresh-families:user123");
    expect(redisClient.del).toHaveBeenCalledWith("sessions:user123");
  });
});
