import { describe, it, expect, vi, beforeEach } from 'vitest';
import jwt from 'jsonwebtoken';
import { randomUUID } from 'crypto';
import { RefreshService, MissingTokenError, InvalidTokenError, type RefreshServiceOptions, type TokenStore } from '../../auth/refreshService';

vi.mock('jsonwebtoken');
vi.mock('crypto', () => ({
  randomUUID: vi.fn(() => 'mock-uuid-1234567890'),
}));

const mockLockInstance = {
  acquire: vi.fn(),
  release: vi.fn(),
};

vi.mock('../../utility/lockHelper', () => ({
  RedisLock: vi.fn(function () {
    return mockLockInstance;
  }),
}));

describe('RefreshService', () => {
  let tokenStore: TokenStore & { compareAndSet?: any };
  let redisClient: any;
  let options: RefreshServiceOptions;
  let service: RefreshService;

  const mockAccessToken = 'new.access.token.jwt';
  const mockRefreshToken = 'valid.refresh.token.jwt';
  const mockNewRefreshToken = 'rotated.refresh.token.jwt';
  const userPayload = { userId: 'user123', email: 'test@example.com', sessionId: 'session-1' };
  const decodedPayload = { userId: 'user123', email: 'test@example.com', sessionId: 'session-1' };

  beforeEach(() => {
    vi.clearAllMocks();

    tokenStore = {
      get: vi.fn(),
      set: vi.fn(),
      del: vi.fn(),
      compareAndSet: vi.fn(),
    } ;

    redisClient = {
      hget: vi.fn().mockResolvedValue(null),
      hset: vi.fn().mockResolvedValue(1),
      hdel: vi.fn().mockResolvedValue(1),
      expire: vi.fn().mockResolvedValue(1),
    };

    options = {
      tokenStore,
      accessTokenSecret: 'access-secret-test',
      refreshTokenSecret: 'refresh-secret-test',
      redisClient,
      accessTokenExpiry: '15m',
      rotateRefreshTokens: false,
      refreshTokenExpiry: '7d',
    };

    service = new RefreshService(options);

    (jwt.sign as any).mockImplementation((payload: any, secret: string) => {
      return secret === options.refreshTokenSecret ? mockRefreshToken : mockAccessToken;
    });
    (jwt.verify as any).mockReturnValue(decodedPayload);
    (jwt.decode as any).mockReturnValue({ exp: Math.floor(Date.now() / 1000) + 3600 });
  });

  describe('generateRefreshToken', () => {
    it('generates token, adds jti, and stores it when tokenStore.set exists', async () => {
      const token = await service.generateRefreshToken(userPayload);

      expect(jwt.sign).toHaveBeenCalledWith(
        { ...userPayload, jti: 'mock-uuid-1234567890' },
        'refresh-secret-test',
        { expiresIn: '7d' }
      );
      expect(tokenStore.set).toHaveBeenCalledWith(
        'refresh:user123:session-1',
        mockRefreshToken,
        60 * 60 * 24 * 7
      );
      expect(token).toBe(mockRefreshToken);
    });

    it('does not call set when tokenStore.set is missing', async () => {
      const storeWithoutSet = { get: vi.fn() } as any;
      const svc = new RefreshService({ ...options, tokenStore: storeWithoutSet });
      
      await expect(svc.generateRefreshToken(userPayload)).resolves.not.toThrow();
      expect(storeWithoutSet.set).toBeUndefined();
    });

    it('throws if userId is missing', async () => {
      await expect(service.generateRefreshToken({ email: 'test@example.com' } as any))
        .rejects.toThrow('generateRefreshToken: payload.userId is missing');
    });
  });

  //======refresh====
  describe('refresh', () => {
    beforeEach(() => {
      mockLockInstance.acquire.mockResolvedValue('lock-value-xyz');
    });

    it('throws MissingTokenError when no refreshToken is provided', async () => {
      await expect(service.refresh(undefined)).rejects.toThrow(MissingTokenError);
    });

    it('throws InvalidTokenError when jwt.verify fails', async () => {
      (jwt.verify as any).mockImplementationOnce(() => { throw new Error('bad jwt'); });
      await expect(service.refresh('bad.token')).rejects.toThrow(InvalidTokenError);
    });

    it('throws InvalidTokenError when lock cannot be acquired (concurrent refresh)', async () => {
      mockLockInstance.acquire.mockResolvedValue(null);
      await expect(service.refresh(mockRefreshToken)).rejects.toThrow(InvalidTokenError);
      expect(mockLockInstance.release).not.toHaveBeenCalled();
    });

    it('throws InvalidTokenError when stored token does not match', async () => {
      vi.mocked(tokenStore.get).mockResolvedValue('different.token');
      await expect(service.refresh(mockRefreshToken)).rejects.toThrow(InvalidTokenError);
    });

    it('successfully refreshes token (no rotation)', async () => {
      vi.mocked(tokenStore.get).mockResolvedValue(mockRefreshToken);

      const result = await service.refresh(mockRefreshToken);

      expect(result.accessToken).toBe(mockAccessToken);
      expect(result.refreshToken).toBe(mockRefreshToken);
      expect(redisClient.hset).toHaveBeenCalledWith(
        'sessions:user123',
        'session-1',
        expect.stringContaining(mockAccessToken)
      );
      expect(mockLockInstance.release).toHaveBeenCalledWith('lock:user123:session-1', 'lock-value-xyz');
    });

    it('rotates refresh token when rotateRefreshTokens = true', async () => {
      const rotatingOptions = { ...options, rotateRefreshTokens: true };
      const rotatingService = new RefreshService(rotatingOptions);

      vi.mocked(tokenStore.get).mockResolvedValue(mockRefreshToken);
      vi.mocked(tokenStore.compareAndSet).mockResolvedValue(true);
      (jwt.sign as any).mockReturnValueOnce(mockNewRefreshToken).mockReturnValueOnce(mockAccessToken);

      const result = await rotatingService.refresh(mockRefreshToken);

      expect(tokenStore.compareAndSet).toHaveBeenCalledWith(
        'refresh:user123:session-1',
        mockRefreshToken,
        mockNewRefreshToken,
        60 * 60 * 24 * 7
      );
      expect(result.refreshToken).toBe(mockNewRefreshToken);
      expect(mockLockInstance.release).toHaveBeenCalled();
    });

    it('detects concurrent refresh during rotation and revokes the token family', async () => {
      const rotatingOptions = { ...options, rotateRefreshTokens: true };
      const rotatingService = new RefreshService(rotatingOptions);

      vi.mocked(tokenStore.get).mockResolvedValue(mockRefreshToken);
      vi.mocked(tokenStore.compareAndSet).mockResolvedValue(false);

      await expect(rotatingService.refresh(mockRefreshToken)).rejects.toThrow(InvalidTokenError);
      expect(tokenStore.del).toHaveBeenCalledWith('refresh:user123:session-1');
      expect(redisClient.hdel).toHaveBeenCalledWith('sessions:user123', 'session-1');
    });

    it('releases lock in finally block even when an error occurs', async () => {
      vi.mocked(tokenStore.get).mockRejectedValue(new Error('redis boom'));
      mockLockInstance.acquire.mockResolvedValue('lock-value-xyz');

      await expect(service.refresh(mockRefreshToken)).rejects.toThrow();

      expect(mockLockInstance.release).toHaveBeenCalledWith('lock:user123:session-1', 'lock-value-xyz');
    });
  });
});
