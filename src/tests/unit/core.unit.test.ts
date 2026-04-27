import { describe, it, expect, vi, beforeEach } from 'vitest';
import { createOAuth } from '../../oauth/core';

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
  const mockRedisClient = {} as any;
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
      mockRedisClient,
      mockIdentityEngine
    );
    expect(mockCreateGitHubProvider).toHaveBeenCalledExactlyOnceWith(
      mockGitHubConfig,
      mockRedisClient,
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
});
