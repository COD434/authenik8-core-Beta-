import { describe, it, expect, vi, beforeEach } from 'vitest';

const {
  mockRedisClient,
  mockTokenStore,
  mockRefreshService,
  mockJwtService,
  mockSecurity,
  mockIdentityEngine,
} = vi.hoisted(() => {
  const mockRedisClient = { on: vi.fn() };
  const mockTokenStore = {};
  
  const mockRefreshService = {
    generateRefreshToken: vi.fn().mockResolvedValue('mock-refresh-token'),
    refresh: vi.fn(),
  };


const mockJwtService = {
  signToken: vi.fn().mockReturnValue('mock-access-token'),
  verifyToken: vi.fn(),
  guestToken: vi.fn(),
};

const mockSecurity = {
  rateLimiterMiddleware: vi.fn().mockReturnValue(vi.fn()),
  whiteListMiddleware: vi.fn().mockReturnValue(vi.fn()),
  helmetMiddleware: vi.fn().mockReturnValue(vi.fn()),
  addIP: vi.fn(),
  removeIP: vi.fn(),
  listIPs: vi.fn(),
};

const mockIdentityEngine = {
  resolveOAuth: vi.fn(),

};
return { mockRedisClient, mockTokenStore, mockRefreshService, mockJwtService, mockSecurity, mockIdentityEngine };
})
import { createOAuth } from '../../oauth/core';
import { createRedisIdentityAdapter } from '../../oauth/adapters/redisAdapter';
import { JWTService } from '../../auth/jwtAuth';
import { initializeRedisClient } from '../../redis/redisService';
import { createAuthenik8 } from '../../createAuthenik8';
import type { Provider } from '../../oauth/userStore';


vi.mock('../../redis/redisService', () => ({
  initializeRedisClient: vi.fn().mockResolvedValue(mockRedisClient),
}));

vi.mock('../../storage/RedisTokenStore', () => ({
  RedisTokenStore: vi.fn().mockImplementation(function () {
    return mockTokenStore;
  }),
}));

vi.mock('../../auth/refreshService', () => ({
  RefreshService: vi.fn().mockImplementation(function () {
    return mockRefreshService;
  }),
}));

vi.mock('../../auth/jwtAuth', () => ({
  JWTService: vi.fn().mockImplementation(function () {
    return mockJwtService;
  }),
}));

vi.mock('../../auth/guestModeService', () => ({
  createIncognito: vi.fn().mockReturnValue(vi.fn()),
}));

vi.mock('../../middleware/adminService', () => ({
  requireAdmin: vi.fn().mockReturnValue(vi.fn()),
}));

vi.mock('../../security/ipService', () => ({
  SecurityModule: vi.fn().mockImplementation(function () {
    return mockSecurity;
  }),
}));

vi.mock('../../oauth/core', () => ({
  createOAuth: vi.fn().mockReturnValue({ mockOAuth: true }),
}));

vi.mock('../../oauth/brain/identityEngine', () => ({
  createIdentityEngine: vi.fn().mockReturnValue(mockIdentityEngine),
}));

vi.mock('../../oauth/adapters/redisAdapter', () => ({
  createRedisIdentityAdapter: vi.fn().mockReturnValue({}),
}));


const baseConfig = {
  jwtSecret: 'test-secret',
  refreshSecret: 'refresh-secret',
};

beforeEach(() => {
  vi.clearAllMocks();
});


describe('createAuthenik8', () => {
  it('returns all expected properties', async () => {
    const instance = await createAuthenik8(baseConfig);

    expect(instance).toMatchObject({
      redisclient: expect.anything(),
      signToken: expect.any(Function),
      verifyToken: expect.any(Function),
      guestToken: expect.any(Function),
      refreshToken: expect.any(Function),
      generateRefreshToken: expect.any(Function),
      rateLimit: expect.any(Function),
      ipWhitelist: expect.any(Function),
      helmet: expect.any(Function),
      addIP: expect.any(Function),
      removeIP: expect.any(Function),
      listIPs: expect.any(Function),
      requireAdmin: expect.any(Function),
      incognito: expect.any(Function),
      issueTokens: expect.any(Function),
      issueTokensFromProfile: expect.any(Function),
    });
  });

  it('uses provided redis client instead of initializing one', async () => {
    const { initializeRedisClient } = await import('../../redis/redisService');
    const customRedis = { on: vi.fn(), custom: true };

    await createAuthenik8({ ...baseConfig, redis: customRedis as any });

    expect(initializeRedisClient).not.toHaveBeenCalled();
  });

  it('initializes redis when none is provided', async () => {
    const { initializeRedisClient } = await import('../../redis/redisService');

    await createAuthenik8(baseConfig);

    expect(initializeRedisClient).toHaveBeenCalled();
  });

  it('creates oauth when config.oauth is provided', async () => {
    const { createOAuth } = await import('../../oauth/core');

    await createAuthenik8({
      ...baseConfig,
      oauth: { github: { clientId: 'id', clientSecret: 'secret', redirectUri: 'uri' } } as any,
    });

    expect(vi.mocked(createOAuth)).toHaveBeenCalled();
  });

  it('leaves oauth undefined when config.oauth is not provided', async () => {
    const instance = await createAuthenik8(baseConfig);
    expect(instance.oauth).toBeUndefined();
  });

  it('uses provided identityAdapter over the default redis adapter', async () => {
    const { createRedisIdentityAdapter } = await import('../../oauth/adapters/redisAdapter');
    const customAdapter = { findUserByEmail: vi.fn() };

    await createAuthenik8({ ...baseConfig, identityAdapter: customAdapter as any });

    expect(createRedisIdentityAdapter).not.toHaveBeenCalled();
  });

  it('defaults jwtExpiry to 15m when not provided', async () => {
    const { JWTService } = await import('../../auth/jwtAuth');

    await createAuthenik8(baseConfig);

    expect(JWTService).toHaveBeenCalledWith(
      expect.objectContaining({ expiry: '15m' })
    );
  });
});


describe('issueTokens', () => {
  it('returns accessToken and refreshToken', async () => {
    const instance = await createAuthenik8(baseConfig);

    const result = await instance.issueTokens({
      userId: 'user-1',
      email: 'test@example.com',
    });

    expect(result).toEqual({
      accessToken: 'mock-access-token',
      refreshToken: 'mock-refresh-token',
    });
  });

  it('calls signToken and generateRefreshToken with correct payload', async () => {
    const instance = await createAuthenik8(baseConfig);

    await instance.issueTokens({ userId: 'user-1', email: 'test@example.com' });

    expect(mockJwtService.signToken).toHaveBeenCalledWith({
      userId: 'user-1',
      email: 'test@example.com',
    });
    expect(mockRefreshService.generateRefreshToken).toHaveBeenCalledWith({
      userId: 'user-1',
      email: 'test@example.com',
    });
  });
});


describe('issueTokensFromProfile', () => {
  const verifiedProfile = {
    email: 'test@example.com',
    provider: 'google' as Provider,
    providerId: 'google-123',
    email_verified: true,
  };

  it('throws when email is not verified', async () => {
    const instance = await createAuthenik8(baseConfig);

    await expect(
      instance.issueTokensFromProfile({ ...verifiedProfile, email_verified: false })
    ).rejects.toThrow('OAuth profile email must be verified before issuing tokens');
  });

  it('throws when email_verified is an unrecognised value', async () => {
    const instance = await createAuthenik8(baseConfig);

    await expect(
      instance.issueTokensFromProfile({ ...verifiedProfile, email_verified: 'false' as any })
    ).rejects.toThrow('OAuth profile email must be verified before issuing tokens');
  });

  it('accepts email_verified as the string "true"', async () => {
    mockIdentityEngine.resolveOAuth.mockResolvedValue({
      type: 'EXISTING_PROVIDER_LOGIN',
      accessToken: 'mock-access-token',
      refreshToken: 'mock-refresh-token',
    });
    const instance = await createAuthenik8(baseConfig);

    const result = await instance.issueTokensFromProfile({
      ...verifiedProfile,
      email_verified: 'true',
    });

    expect(result.accessToken).toBe('mock-access-token');
  });

  it('returns tokens for EXISTING_PROVIDER_LOGIN', async () => {
    mockIdentityEngine.resolveOAuth.mockResolvedValue({
      type: 'EXISTING_PROVIDER_LOGIN',
      accessToken: 'mock-access-token',
      refreshToken: 'mock-refresh-token',
    });
    const instance = await createAuthenik8(baseConfig);

    const result = await instance.issueTokensFromProfile(verifiedProfile);

    expect(result).toEqual({
      accessToken: 'mock-access-token',
      refreshToken: 'mock-refresh-token',
    });
  });

  it('returns tokens for NEW_USER_CREATION', async () => {
    mockIdentityEngine.resolveOAuth.mockResolvedValue({
      type: 'NEW_USER_CREATION',
      accessToken: 'mock-access-token',
      refreshToken: 'mock-refresh-token',
    });
    const instance = await createAuthenik8(baseConfig);

    const result = await instance.issueTokensFromProfile(verifiedProfile);

    expect(result.accessToken).toBe('mock-access-token');
  });

  it('throws the message from LINK_REQUIRED result', async () => {
    mockIdentityEngine.resolveOAuth.mockResolvedValue({
      type: 'LINK_REQUIRED',
      message: 'please link manually',
    });
    const instance = await createAuthenik8(baseConfig);

    await expect(
      instance.issueTokensFromProfile(verifiedProfile)
    ).rejects.toThrow('please link manually');
  });

  it('throws generic error for unexpected result types', async () => {
    mockIdentityEngine.resolveOAuth.mockResolvedValue({
      type: 'INVALID_LINK_REQUEST',
    });
    const instance = await createAuthenik8(baseConfig);

    await expect(
      instance.issueTokensFromProfile(verifiedProfile)
    ).rejects.toThrow('OAuth token issuance failed');
  });

  it('calls resolveOAuth in login mode with null userId', async () => {
    mockIdentityEngine.resolveOAuth.mockResolvedValue({
      type: 'EXISTING_PROVIDER_LOGIN',
      accessToken: 'mock-access-token',
      refreshToken: 'mock-refresh-token',
    });
    const instance = await createAuthenik8(baseConfig);

    await instance.issueTokensFromProfile(verifiedProfile);

    expect(mockIdentityEngine.resolveOAuth).toHaveBeenCalledWith({
      profile: verifiedProfile,
      mode: 'login',
      userId: null,
    });
  });
});
