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
      mockIdentityEngine
    );
    expect(mockCreateGitHubProvider).toHaveBeenCalledExactlyOnceWith(
      mockGitHubConfig,
      expect.objectContaining({
        set: expect.any(Function),
        get: expect.any(Function),
        del: expect.any(Function),
      }),
      mockIdentityEngine
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

    await stateStore.set('state-1', { userId: 'u1', mode: 'link' }, 300);
    const state = await stateStore.get('state-1');
    await stateStore.del('state-1');

    expect(mockRedisClient.setex).toHaveBeenCalledWith(
      'oauth:state:state-1',
      300,
      JSON.stringify({ userId: 'u1', mode: 'link' })
    );
    expect(state).toEqual({ userId: 'u1', mode: 'link' });
    expect(mockRedisClient.del).toHaveBeenCalledWith('oauth:state:state-1');
  });
});
