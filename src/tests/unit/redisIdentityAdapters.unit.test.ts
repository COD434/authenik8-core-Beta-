import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { Redis } from 'ioredis';
import { createRedisIdentityAdapter } from '../../oauth/adapters/redisAdapter';
const mockLockInstance = {
  acquire: vi.fn(),
  release: vi.fn(),
};

vi.mock('../../utility/lockHelper', () => ({
  RedisLock: vi.fn(function () {
    return mockLockInstance;
  }),
}));

const mockMultiInstance = {
  set: vi.fn().mockReturnThis(),
  exec: vi.fn().mockResolvedValue([['OK'], ['OK'], ['OK']]),
};

const mockRedis = {
  get: vi.fn(),
  set: vi.fn().mockResolvedValue('OK'),
  eval: vi.fn().mockResolvedValue(1),
  multi: vi.fn(() => mockMultiInstance),
} as any;

describe('createRedisIdentityAdapter', () => {
  let adapter: ReturnType<typeof createRedisIdentityAdapter>;

  const mockEmail = 'test@example.com';
  const mockProvider = 'google';
  const mockProviderId = 'google-123';
  const mockUserId = 'user-uuid-123';
  const mockUser = {
    id: mockUserId,
    email: mockEmail.toLowerCase(),
    providers: [{ provider: mockProvider, providerId: mockProviderId }],
  };

  beforeEach(() => {
    vi.clearAllMocks();
    adapter = createRedisIdentityAdapter(mockRedis as Redis);

    // Default successful lock
    mockLockInstance.acquire.mockResolvedValue('lock-value-xyz');
    mockLockInstance.release.mockResolvedValue(undefined);
  });

  describe('findUserByEmail', () => {
    it('returns null when user does not exist', async () => {
      mockRedis.get.mockResolvedValue(null);
      const user = await adapter.findUserByEmail(mockEmail);
      expect(user).toBeNull();
    });

    it('returns the user when found', async () => {
      mockRedis.get.mockResolvedValueOnce(mockUserId); // email key
      mockRedis.get.mockResolvedValueOnce(JSON.stringify(mockUser)); // user key

      const user = await adapter.findUserByEmail(mockEmail);                                               expect(user).toEqual(mockUser);                                                                    });
  });

  describe('findUserByProvider', () => {
    it('returns null when no matching provider', async () => {
      mockRedis.get.mockResolvedValue(null);
      const user = await adapter.findUserByProvider(mockProvider, mockProviderId);
      expect(user).toBeNull();
    });

    it('returns the user when provider is linked', async () => {
      mockRedis.get.mockResolvedValueOnce(mockUserId); // provider key
      mockRedis.get.mockResolvedValueOnce(JSON.stringify(mockUser));
                                                                                                           const user = await adapter.findUserByProvider(mockProvider, mockProviderId);
      expect(user).toEqual(mockUser);
    });                                                                                                });

  describe('createUser', () => {
    it('throws if email lock cannot be acquired', async () => {
      mockLockInstance.acquire.mockResolvedValueOnce(null); // email lock fails

      await expect(
        adapter.createUser({ email: mockEmail, provider: mockProvider, providerId: mockProviderId })
      ).rejects.toThrow('Unable to acquire OAuth email lock');
    });

    it('throws if provider lock cannot be acquired (and releases email lock)', async () => {
      mockLockInstance.acquire.mockResolvedValueOnce('email-lock');
      mockLockInstance.acquire.mockResolvedValueOnce(null); // provider lock fails

      await expect(                                                                                          adapter.createUser({ email: mockEmail, provider: mockProvider, providerId: mockProviderId })
      ).rejects.toThrow('Unable to acquire OAuth provider lock');

      expect(mockLockInstance.release).toHaveBeenCalledWith(
        expect.stringContaining(':lock:email:'),
        'email-lock'
      );
    });

    it('returns existing user if already registered by email', async () => {
      mockRedis.get.mockResolvedValueOnce(mockUserId); // email key exiss
      mockRedis.get.mockResolvedValueOnce(JSON.stringify(mockUser))

      const user = await adapter.createUser({
        email: mockEmail,
        provider: mockProvider,
        providerId: mockProviderId,
      });

      expect(user).toEqual(mockUser);
      expect(mockRedis.multi).not.toHaveBeenCalled(); // no new write
    });

    it('returns existing user if already registered by provider', async () => {
      mockRedis.get.mockResolvedValueOnce(null); // email not found
      mockRedis.get.mockResolvedValueOnce(mockUserId); // provider key exists
      mockRedis.get.mockResolvedValueOnce(JSON.stringify(mockUser));

      const user = await adapter.createUser({
        email: mockEmail,
        provider: mockProvider,
        providerId: mockProviderId,
      });

      expect(user).toEqual(mockUser);                                                                    });

    it('creates a brand new user with Redis multi transaction', async () => {
      // no existing user
      mockRedis.get.mockResolvedValue(null);

      const user = await adapter.createUser({
        email: mockEmail,
        provider: mockProvider,                                                                              providerId: mockProviderId,
      });

      expect(user.id).toBeDefined();
      expect(user.email).toBe(mockEmail.toLowerCase());
      expect(user.providers).toHaveLength(1);

      expect(mockRedis.multi).toHaveBeenCalled();
      expect(mockMultiInstance.set).toHaveBeenCalledTimes(3); 
      expect(mockLockInstance.release).toHaveBeenCalledTimes(2);
    });
  });

  describe('linkProvider', () => {
    it('throws if provider lock cannot be acquired', async () => {
      mockLockInstance.acquire.mockResolvedValue(null);

      await expect(
        adapter.linkProvider(mockUserId, mockProvider, 'new-id')
      ).rejects.toThrow('Unable to acquire OAuth provider lock');
    });

    it('throws if provider is already linked to another user', async () => {
      mockLockInstance.acquire.mockResolvedValue('provider-lock');
      mockRedis.get.mockResolvedValueOnce('different-user-id'); 

      await expect(
        adapter.linkProvider(mockUserId, mockProvider, mockProviderId)
      ).rejects.toThrow('Provider already linked to another user');
    });

    it('throws if user does not exist', async () => {
      mockLockInstance.acquire.mockResolvedValue('provider-lock');
      mockRedis.get.mockResolvedValueOnce(null); 
      mockRedis.get.mockResolvedValueOnce(null); 

      await expect(
        adapter.linkProvider(mockUserId, mockProvider, mockProviderId)
      ).rejects.toThrow(`User not found: ${mockUserId}`);
    });

    it('adds new provider (or ignores duplicate) and updates Redis', async () => {
      mockLockInstance.acquire.mockResolvedValue('provider-lock');
      mockRedis.get.mockResolvedValueOnce(null); 
      mockRedis.get.mockResolvedValueOnce(JSON.stringify(mockUser)); 

      await adapter.linkProvider(mockUserId, 'github', 'github-999');

      expect(mockRedis.multi).toHaveBeenCalled();
      expect(mockMultiInstance.set).toHaveBeenCalledTimes(3);
      expect(mockLockInstance.release).toHaveBeenCalledWith(
        expect.stringContaining(':lock:provider:'),
        'provider-lock'
      );
    });
  });
});
