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
    });
    expect(instance).not.toHaveProperty('issueTokensFromProfile');
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
    expect(vi.mocked(createOAuth)).toHaveBeenCalledWith(
      expect.objectContaining({ identityEngine: mockIdentityEngine })
    );
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

    expect(mockJwtService.signToken).toHaveBeenCalledWith(expect.objectContaining({
      userId: 'user-1',
      email: 'test@example.com',
      sessionId: expect.any(String),
    }));
    expect(mockRefreshService.generateRefreshToken).toHaveBeenCalledWith(expect.objectContaining({
      userId: 'user-1',
      email: 'test@example.com',
      sessionId: expect.any(String),
    }));
  });
});
