import { describe, it, expect, vi, beforeEach } from 'vitest';
import { createOAuth, createRedisOAuthStateStore } from '../../oauth/core';

const mockCreateGoogleProvider = vi.hoisted(() => vi.fn());
const mockCreateGitHubProvider = vi.hoisted(() => vi.fn());

vi.mock('../../oauth/providers/google', () => ({
  createGoogleProvider: mockCreateGoogleProvider,
}));

vi.mock('../../oauth/providers/github', () => ({
  createGitHubProvider: mockCreateGitHubProvider,
}));


describe('createOAuth', () => {
  const mockGoogleConfig = { clientId: 'google-123', clientSecret: 'secret' } as any;
  const mockGitHubConfig = { clientId: 'github-456', clientSecret: 'secret' } as any;
  const mockRedisClient = {
    setex: vi.fn(),
    get: vi.fn(),
    del: vi.fn(),
    getdel: vi.fn(),
  };
  const mockIdentityEngine = {} as any;

  beforeEach(() => {
    vi.clearAllMocks();
    mockCreateGoogleProvider.mockReturnValue({ name: 'google-provider' });
    mockCreateGitHubProvider.mockReturnValue({ name: 'github-provider' });
  });

  it('creates both providers when both are configured', () => {
    const config = {
      google: mockGoogleConfig,
      github: mockGitHubConfig,
      redisClient: mockRedisClient,
      identityEngine: mockIdentityEngine,
    };

    const oauth = createOAuth(config);

    expect(mockCreateGoogleProvider).toHaveBeenCalledExactlyOnceWith(
      mockGoogleConfig,
      expect.objectContaining({
        set: expect.any(Function),
        get: expect.any(Function),
        del: expect.any(Function),
      }),
      mockIdentityEngine,
      undefined,
    );
    expect(mockCreateGitHubProvider).toHaveBeenCalledExactlyOnceWith(
      mockGitHubConfig,
      expect.objectContaining({
        set: expect.any(Function),
        get: expect.any(Function),
        del: expect.any(Function),
      }),
      mockIdentityEngine,
      undefined,
    );

    expect(oauth).toEqual({
      google: { name: 'google-provider' },
      github: { name: 'github-provider' },
    });
  });

  it('creates only Google provider when only Google config is provided', () => {
    const config = {
      google: mockGoogleConfig,
      redisClient: mockRedisClient,
      identityEngine: mockIdentityEngine,
    };

    const oauth = createOAuth(config);

    expect(mockCreateGoogleProvider).toHaveBeenCalledOnce();
    expect(mockCreateGitHubProvider).not.toHaveBeenCalled();
    expect(oauth.google).toBeDefined();
    expect(oauth.github).toBeUndefined();
  });

  it('creates only GitHub provider when only GitHub config is provided', () => {
    const config = {
      github: mockGitHubConfig,
      redisClient: mockRedisClient,
      identityEngine: mockIdentityEngine,
    };

    const oauth = createOAuth(config);

    expect(mockCreateGitHubProvider).toHaveBeenCalledOnce();
    expect(mockCreateGoogleProvider).not.toHaveBeenCalled();
    expect(oauth.github).toBeDefined();
    expect(oauth.google).toBeUndefined();
  });

  it('returns undefined for both when neither provider is configured', () => {
    const config = {
      redisClient: mockRedisClient,
      identityEngine: mockIdentityEngine,
    };

    const oauth = createOAuth(config);

    expect(mockCreateGoogleProvider).not.toHaveBeenCalled();
    expect(mockCreateGitHubProvider).not.toHaveBeenCalled();
    expect(oauth.google).toBeUndefined();
    expect(oauth.github).toBeUndefined();
  });

  it('adapts Redis commands behind the OAuth state-store contract', async () => {
    mockRedisClient.get.mockResolvedValueOnce(JSON.stringify({ userId: 'u1', mode: 'link' }));
    const stateStore = createRedisOAuthStateStore(mockRedisClient);
    const stateToken = "a".repeat(64);

    await stateStore.set(stateToken, { userId: 'u1', mode: 'link' }, 300);
    const state = await stateStore.get!(stateToken);
    await stateStore.del!(stateToken);

    expect(mockRedisClient.setex).toHaveBeenCalledWith(
      `oauth:state:${stateToken}`,
      300,
      JSON.stringify({ userId: 'u1', mode: 'link' })
    );
    expect(state).toEqual({ userId: 'u1', mode: 'link' });
    expect(mockRedisClient.del).toHaveBeenCalledWith(`oauth:state:${stateToken}`);
  });

  it('consumes a state value exactly once through atomic GETDEL', async () => {
    const stateToken = "b".repeat(64);
    mockRedisClient.getdel
      .mockResolvedValueOnce(JSON.stringify({ userId: null, mode: "login" }))
      .mockResolvedValueOnce(null);
    const stateStore = createRedisOAuthStateStore(mockRedisClient);

    const [first, replay] = await Promise.all([
      stateStore.take(stateToken),
      stateStore.take(stateToken),
    ]);

    expect(first).toEqual({ userId: null, mode: "login" });
    expect(replay).toBeNull();
    expect(mockRedisClient.get).not.toHaveBeenCalled();
    expect(mockRedisClient.del).not.toHaveBeenCalled();
  });

  it("rejects oversized, extended, and control-character state records", async () => {
    const stateToken = "c".repeat(64);
    const stateStore = createRedisOAuthStateStore(mockRedisClient);

    mockRedisClient.getdel.mockResolvedValueOnce(
      JSON.stringify({
        userId: null,
        mode: "login",
        injected: "not part of the state contract",
      }),
    );
    await expect(stateStore.take(stateToken)).resolves.toBeNull();

    mockRedisClient.getdel.mockResolvedValueOnce(
      JSON.stringify({ userId: "user\nadmin", mode: "link" }),
    );
    await expect(stateStore.take(stateToken)).resolves.toBeNull();

    mockRedisClient.getdel.mockResolvedValueOnce(`"${"x".repeat(2048)}"`);
    await expect(stateStore.take(stateToken)).resolves.toBeNull();
  });

  it('rejects custom state stores that do not provide atomic take', () => {
    expect(() =>
      createOAuth({
        google: mockGoogleConfig,
        stateStore: {
          set: vi.fn(),
        } as any,
      }),
    ).toThrow(/atomic take/);
  });
});
