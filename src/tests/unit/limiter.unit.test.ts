import { describe, it, expect, vi, beforeEach } from 'vitest';
import { TokenBucket, createRatelimiter, initializeRateLimiter } from '../../security/limiter';
import type { Request, Response, NextFunction } from 'express';

const { mockRedis, mockPipeline,mockRateLimiter } = vi.hoisted(() => {
  const mockPipeline = {
    hgetall: vi.fn().mockReturnThis(),
    exec: vi.fn(),
  };
  const mockRedis = {
    pipeline: vi.fn(() => mockPipeline),
    hset: vi.fn().mockResolvedValue(1),
    expire: vi.fn().mockResolvedValue(1),
  };
  const mockRateLimiter = { consume: vi.fn() };
  return { mockRedis, mockPipeline,mockRateLimiter };
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

function makeBucketState(tokens: number, lastRefill: number) {
  return [[null, { tokens: tokens.toString(), lastRefill: lastRefill.toString() }]];
}

beforeEach(() => {
  vi.clearAllMocks();
});


describe('TokenBucket', () => {
  let bucket: InstanceType<typeof TokenBucket>;

  beforeEach(() => {
    bucket = new TokenBucket(mockRedis as any);
  });

  it('allows request when tokens are available', async () => {
    mockPipeline.exec.mockResolvedValue(makeBucketState(5, Date.now()));

    const result = await bucket.consume('test-key', 10, 1);

    expect(result.allowed).toBe(true);
    expect(result.remaining).toBeGreaterThanOrEqual(0);
    expect(mockRedis.hset).toHaveBeenCalled();
  });

  it('denies request when tokens are exhausted', async () => {
    mockPipeline.exec.mockResolvedValue(makeBucketState(0.5, Date.now()));

    const result = await bucket.consume('test-key', 10, 1);

    expect(result.allowed).toBe(false);
    expect(result.remaining).toBe(0);
    expect(result.retryAfter).toBeGreaterThan(0);
    expect(mockRedis.hset).not.toHaveBeenCalled();
  });

  it('refills tokens based on elapsed time', async () => {
    const fiveSecondsAgo = Date.now() - 5000;
    // Start with 0 tokens, refillRate=2/s → should refill 10 tokens over 5s
    mockPipeline.exec.mockResolvedValue(makeBucketState(0, fiveSecondsAgo));

    const result = await bucket.consume('test-key', 10, 2);

    expect(result.allowed).toBe(true);
  });

  it('caps refilled tokens at capacity', async () => {
    const longAgo = Date.now() - 99999000;
    mockPipeline.exec.mockResolvedValue(makeBucketState(0, longAgo));

    const result = await bucket.consume('test-key', 5, 10);

    // Remaining after consuming 1 from a full bucket of 5
    expect(result.remaining).toBe(4);
  });

  it('uses capacity as default when bucket state is empty', async () => {
    mockPipeline.exec.mockResolvedValue([[null, {}]]);

    const result = await bucket.consume('test-key', 10, 1);

    expect(result.allowed).toBe(true);
    expect(mockRedis.hset).toHaveBeenCalled();
  });

  it('handles null pipeline result gracefully', async () => {
    mockPipeline.exec.mockResolvedValue(null);

    const result = await bucket.consume('test-key', 10, 1);

    expect(result.allowed).toBe(true);
  });

  it('sets expiry on the rate limit key after consuming', async () => {
    mockPipeline.exec.mockResolvedValue(makeBucketState(5, Date.now()));

    await bucket.consume('test-key', 10, 1);

    expect(mockRedis.expire).toHaveBeenCalledWith('rate_limit:test-key', 3600);
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
    mockPipeline.exec.mockResolvedValue(makeBucketState(5, Date.now()));
    await initializeRateLimiter(); // prime the singleton

    const middleware = createRatelimiter(config);
    await middleware(mockReq(), mockRes(), next);

    expect(next).toHaveBeenCalled();
  });

  it('returns 429 when request is denied', async () => {
    mockPipeline.exec.mockResolvedValue(makeBucketState(0.5, Date.now()));
    await initializeRateLimiter();

    const middleware = createRatelimiter(config);
    const res = mockRes();
    await middleware(mockReq(), res, next);

    expect(res.status).toHaveBeenCalledWith(429);
    expect(res.json).toHaveBeenCalledWith({ error: 'Too many requests' });
    expect(next).not.toHaveBeenCalled();
  });

  it('sets X-RateLimit headers on every response', async () => {
    mockPipeline.exec.mockResolvedValue(makeBucketState(5, Date.now()));
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
    mockPipeline.exec.mockResolvedValue(makeBucketState(0.5, Date.now()));
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
    mockPipeline.exec.mockResolvedValue(makeBucketState(5, Date.now()));
    await initializeRateLimiter();

    const customConfig = {
      ...config,
      keyGenerator: (req: Request) => (req as any).body?.email || 'fallback',
    };
    const middleware = createRatelimiter(customConfig);
    await middleware(mockReq({ body: { email: 'user@example.com' } }), mockRes(), next);

    expect(mockRedis.hset).toHaveBeenCalledWith(
      'rate_limit:user@example.com',
      expect.any(Object)
    );
  });
});
