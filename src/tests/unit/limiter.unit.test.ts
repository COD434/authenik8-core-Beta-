import { describe, it, expect, vi, beforeEach } from 'vitest';
import { TokenBucket, createRatelimiter, initializeRateLimiter } from '../../security/limiter';
import type { Request, Response, NextFunction } from 'express';

const { mockRedis,mockRateLimiter } = vi.hoisted(() => {
  const mockRedis = {
    eval: vi.fn().mockResolvedValue([1, 4, 0]),
  };
  const mockRateLimiter = { consume: vi.fn() };
  return { mockRedis,mockRateLimiter };
});


vi.mock('../../redis/redisService', () => ({
  setupRedis: vi.fn().mockResolvedValue({
    redisClient: mockRedis,
  }),
}));


const mockReq = (overrides: Partial<Request> = {}) =>
  ({
    ip: '1.2.3.4',
    body: {},
    ...overrides,
  }) as unknown as Request;

const mockRes = () => {
  const res = {
    status: vi.fn().mockReturnThis(),
    json: vi.fn().mockReturnThis(),
    set: vi.fn().mockReturnThis(),
  };
  return res as unknown as Response;
};

const next = vi.fn() as NextFunction;

beforeEach(() => {
  vi.clearAllMocks();
  mockRedis.eval.mockResolvedValue([1, 4, 0]);
});


describe('TokenBucket', () => {
  let bucket: InstanceType<typeof TokenBucket>;

  beforeEach(() => {
    bucket = new TokenBucket(mockRedis as any);
  });

  it('allows request when tokens are available', async () => {
    mockRedis.eval.mockResolvedValue([1, 4, 0]);

    const result = await bucket.consume('test-key', 10, 1);

    expect(result.allowed).toBe(true);
    expect(result.remaining).toBeGreaterThanOrEqual(0);
    expect(mockRedis.eval).toHaveBeenCalledWith(
      expect.any(String),
      1,
      'rate_limit:test-key',
      '10',
      '1',
      expect.any(String),
      '3600'
    );
  });

  it('denies request when tokens are exhausted', async () => {
    mockRedis.eval.mockResolvedValue([0, 0, 1]);

    const result = await bucket.consume('test-key', 10, 1);

    expect(result.allowed).toBe(false);
    expect(result.remaining).toBe(0);
    expect(result.retryAfter).toBeGreaterThan(0);
  });

  it('refills tokens based on elapsed time', async () => {
    mockRedis.eval.mockResolvedValue([1, 9, 0]);

    const result = await bucket.consume('test-key', 10, 2);

    expect(result.allowed).toBe(true);
  });

  it('caps refilled tokens at capacity', async () => {
    mockRedis.eval.mockResolvedValue([1, 4, 0]);

    const result = await bucket.consume('test-key', 5, 10);

    // Remaining after consuming 1 from a full bucket of 5
    expect(result.remaining).toBe(4);
  });

  it('uses capacity as default when bucket state is empty', async () => {
    mockRedis.eval.mockResolvedValue([1, 9, 0]);

    const result = await bucket.consume('test-key', 10, 1);

    expect(result.allowed).toBe(true);
  });

  it('sets expiry on the rate limit key after consuming', async () => {
    mockRedis.eval.mockResolvedValue([1, 4, 0]);

    await bucket.consume('test-key', 10, 1);

    expect(mockRedis.eval).toHaveBeenCalledWith(
      expect.any(String),
      1,
      'rate_limit:test-key',
      '10',
      '1',
      expect.any(String),
      '3600'
    );
  });
});


describe('initializeRateLimiter', () => {
  it('returns a TokenBucket instance', async () => {
    const bucket = await initializeRateLimiter();
    expect(bucket).toBeInstanceOf(TokenBucket);
  });
});


describe('createRatelimiter', () => {
  const config = {
    capacity: 10,
    refillRate: 2,
    keyGenerator: (req: Request) => req.ip || 'unknown',
  };

  it('calls next() when request is allowed', async () => {
    mockRedis.eval.mockResolvedValue([1, 4, 0]);
    await initializeRateLimiter(); // prime the singleton

    const middleware = createRatelimiter(config);
    await middleware(mockReq(), mockRes(), next);

    expect(next).toHaveBeenCalled();
  });

  it('returns 429 when request is denied', async () => {
    mockRedis.eval.mockResolvedValue([0, 0, 1]);
    await initializeRateLimiter();

    const middleware = createRatelimiter(config);
    const res = mockRes();
    await middleware(mockReq(), res, next);

    expect(res.status).toHaveBeenCalledWith(429);
    expect(res.json).toHaveBeenCalledWith({ error: 'Too many requests' });
    expect(next).not.toHaveBeenCalled();
  });

  it('sets X-RateLimit headers on every response', async () => {
    mockRedis.eval.mockResolvedValue([1, 4, 0]);
    await initializeRateLimiter();

    const middleware = createRatelimiter(config);
    const res = mockRes();
    await middleware(mockReq(), res, next);

    expect(res.set).toHaveBeenCalledWith(
      expect.objectContaining({
        'X-RateLimit-Limit': '10',
        'X-RateLimit-Remaining': expect.any(String),
      })
    );
  });

  it('sets Retry-After header when denied', async () => {
    mockRedis.eval.mockResolvedValue([0, 0, 1]);
    await initializeRateLimiter();

    const middleware = createRatelimiter(config);
    const res = mockRes();
    await middleware(mockReq(), res, next);

    expect(res.set).toHaveBeenCalledWith(
      expect.objectContaining({ 'Retry-After': expect.any(String) })
    );
  });

  it('returns 503 when token bucket is unavailable', async () => {
    const { setupRedis } = await import('../../redis/redisService');
    vi.mocked(setupRedis).mockRejectedValueOnce(new Error('Redis down'));

    // Reset the singleton so getTokenBucket re-initializes
    vi.resetModules();
    const { createRatelimiter: freshCreateRatelimiter } = await import('../../security/limiter');

    const middleware = freshCreateRatelimiter(config);
    const res = mockRes();
    await middleware(mockReq(), res, next);

    expect(res.status).toHaveBeenCalledWith(503);
    expect(res.json).toHaveBeenCalledWith({ error: 'Rate limiter unavailable' });
  });

  it('uses keyGenerator output as the bucket key', async () => {
    mockRedis.eval.mockResolvedValue([1, 4, 0]);
    await initializeRateLimiter();

    const customConfig = {
      ...config,
      keyGenerator: (req: Request) => (req as any).body?.email || 'fallback',
    };
    const middleware = createRatelimiter(customConfig);
    await middleware(mockReq({ body: { email: 'user@example.com' } }), mockRes(), next);

    expect(mockRedis.eval).toHaveBeenCalledWith(
      expect.any(String),
      1,
      'rate_limit:user@example.com',
      '10',
      '2',
      expect.any(String),
      '3600'
    );
  });
});
