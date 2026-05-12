import { describe, it, expect, vi, beforeEach } from 'vitest';
import { SecurityModule } from '../../security/ipService';
import type { Request, Response, NextFunction } from 'express';


vi.mock('ioredis', () => {
  const Redis = vi.fn(() => mockRedis);
  return { default: Redis };
});

vi.mock('rate-limiter-flexible', () => ({
  RateLimiterRedis: vi.fn(() => mockRateLimiter),
}));

vi.mock('ip-address', async(importOriginal) => {
return  await importOriginal();    
})

const mockRateLimiter = {
  consume: vi.fn(),
};

const mockRedis = {
  on: vi.fn(),
  sadd: vi.fn().mockResolvedValue(1),
  srem: vi.fn().mockResolvedValue(1),
  sismember: vi.fn().mockResolvedValue(0),
  smembers: vi.fn().mockResolvedValue([]),
  set: vi.fn().mockResolvedValue('OK'),
  del: vi.fn().mockResolvedValue(1),
  exists: vi.fn().mockResolvedValue(1),
};

const mockReq = (overrides: Partial<Request> = {}) =>
  ({
    ip: '1.2.3.4',
    socket: { remoteAddress: '1.2.3.4' },
    headers: {},
    ...overrides,
  }) as unknown as Request;

const mockRes = () => {
  const res = {
    status: vi.fn().mockReturnThis(),
    json: vi.fn().mockReturnThis(),
    send: vi.fn().mockReturnThis(),
  };
  return res as unknown as Response;
};

const next: NextFunction = vi.fn();

beforeEach(() => {
  vi.clearAllMocks();
  mockRedis.sismember.mockResolvedValue(0);
  mockRedis.smembers.mockResolvedValue([]);
  mockRedis.exists.mockResolvedValue(1);
});


describe('isAllowed', () => {
  it('returns true immediately when whitelist is disabled', async () => {
    const module = new SecurityModule({
      redisClient: mockRedis as any,
      whiteListEnabled: false,
    });

    const result = await module.isAllowed('9.9.9.9');
    expect(result).toBe(true);
    expect(mockRedis.sismember).not.toHaveBeenCalled();
  });

  it('returns true when IP is in the Redis set', async () => {
    mockRedis.sismember.mockResolvedValue(1);
    const module = new SecurityModule({ redisClient: mockRedis as any });

    expect(await module.isAllowed('5.5.5.5')).toBe(true);
  });

  it('returns true for localhost ::1', async () => {
    const module = new SecurityModule({ redisClient: mockRedis as any });
    expect(await module.isAllowed('::1')).toBe(true);
  });

  it('returns true for localhost 127.0.0.1', async () => {
    const module = new SecurityModule({ redisClient: mockRedis as any });
    expect(await module.isAllowed('127.0.0.1')).toBe(true);
  });

  it('returns true for IP matching a CIDR entry', async () => {
    mockRedis.smembers.mockResolvedValue(['10.0.0.0/8']);
    mockRedis.exists.mockResolvedValue(1);
    const module = new SecurityModule({ redisClient: mockRedis as any });

    expect(await module.isAllowed('10.1.2.3')).toBe(true);
  });

  it('returns false for IP not in whitelist or CIDR', async () => {
    mockRedis.smembers.mockResolvedValue([]);
    const module = new SecurityModule({ redisClient: mockRedis as any });

    expect(await module.isAllowed('8.8.8.8')).toBe(false);
  });

  it('returns false when Redis throws', async () => {
    mockRedis.sismember.mockRejectedValue(new Error('Redis down'));
    const module = new SecurityModule({ redisClient: mockRedis as any });

    expect(await module.isAllowed('1.2.3.4')).toBe(false);
  });
});


describe('addIP', () => {
  it('calls sadd and set with the correct keys', async () => {
    const module = new SecurityModule({ redisClient: mockRedis as any });
    await module.addIP('5.5.5.5');

    expect(mockRedis.sadd).toHaveBeenCalledWith('whitelist:ips', '5.5.5.5');
    expect(mockRedis.set).toHaveBeenCalledWith(
      expect.stringContaining('whitelist:ips:entry:'),
      '1',
      'EX',
      604800 // 7 days
    );
  });

  it('accepts a custom TTL', async () => {
    const module = new SecurityModule({ redisClient: mockRedis as any });
    await module.addIP('5.5.5.5', 3600);

    expect(mockRedis.set).toHaveBeenCalledWith(
      expect.any(String),
      '1',
      'EX',
      3600
    );
  });
});


describe('removeIP', () => {
  it('calls srem and del with the correct keys', async () => {
    const module = new SecurityModule({ redisClient: mockRedis as any });
    await module.removeIP('5.5.5.5');

    expect(mockRedis.srem).toHaveBeenCalledWith('whitelist:ips', '5.5.5.5');
    expect(mockRedis.del).toHaveBeenCalledWith(
      expect.stringContaining('whitelist:ips:entry:')
    );
  });
});


describe('listIPs', () => {
  it('returns only entries whose TTL key still exists', async () => {
    mockRedis.smembers.mockResolvedValue(['1.1.1.1', '2.2.2.2']);
    mockRedis.exists
      .mockResolvedValueOnce(1) // 1.1.1.1 active
      .mockResolvedValueOnce(0); // 2.2.2.2 expired

    const module = new SecurityModule({ redisClient: mockRedis as any });
    const result = await module.listIPs();

    expect(result).toEqual(['1.1.1.1']);
    expect(mockRedis.srem).toHaveBeenCalledWith('whitelist:ips', '2.2.2.2');
  });

  it('returns empty array when no IPs are stored', async () => {
    mockRedis.smembers.mockResolvedValue([]);
    const module = new SecurityModule({ redisClient: mockRedis as any });

    expect(await module.listIPs()).toEqual([]);
  });
});


describe('whiteListMiddleware', () => {
  it('calls next() immediately when whitelist is disabled', async () => {
    const module = new SecurityModule({
      redisClient: mockRedis as any,
      whiteListEnabled: false,
    });
    const middleware = module.whiteListMiddleware();
    await middleware(mockReq(), mockRes(), next);

    expect(next).toHaveBeenCalled();
  });

  it('calls next() when IP is allowed', async () => {
    mockRedis.sismember.mockResolvedValue(1);
    const module = new SecurityModule({ redisClient: mockRedis as any });
    const middleware = module.whiteListMiddleware();
    await middleware(mockReq({ ip: '5.5.5.5' }), mockRes(), next);

    expect(next).toHaveBeenCalled();
  });

  it('returns 403 when IP is not allowed', async () => {
    mockRedis.sismember.mockResolvedValue(0);
    mockRedis.smembers.mockResolvedValue([]);
    const module = new SecurityModule({ redisClient: mockRedis as any });
    const res = mockRes();
    const middleware = module.whiteListMiddleware();
    await middleware(mockReq({ ip: '9.9.9.9' }), res, next);

    expect(res.status).toHaveBeenCalledWith(403);
    expect(res.json).toHaveBeenCalledWith({ error: 'Access denied' });
    expect(next).not.toHaveBeenCalled();
  });

  it('uses x-forwarded-for when trustProxyHeaders is true', async () => {
    mockRedis.sismember.mockResolvedValue(1);
    const module = new SecurityModule({
      redisClient: mockRedis as any,
      trustProxyHeaders: true,
    });
    const req = mockReq({
      headers: { 'x-forwarded-for': '203.0.113.5, 10.0.0.1' },
    });
    const middleware = module.whiteListMiddleware();
    await middleware(req, mockRes(), next);

    expect(mockRedis.sismember).toHaveBeenCalledWith(
      'whitelist:ips',
      '203.0.113.5'
    );
  });

  it('ignores x-forwarded-for when trustProxyHeaders is false', async () => {
    mockRedis.sismember.mockResolvedValue(1);
    const module = new SecurityModule({
      redisClient: mockRedis as any,
      trustProxyHeaders: false,
    });
    const req = mockReq({
      ip: '1.2.3.4',
      headers: { 'x-forwarded-for': '203.0.113.5' },
    });
    const middleware = module.whiteListMiddleware();
    await middleware(req, mockRes(), next);

    expect(mockRedis.sismember).toHaveBeenCalledWith('whitelist:ips', '1.2.3.4');
  });
});


describe('rateLimiterMiddleware', () => {
  it('calls next() when rate limit is not exceeded', async () => {
    mockRateLimiter.consume.mockResolvedValue(undefined);
    const module = new SecurityModule({ redisClient: mockRedis as any });
    const middleware = module.rateLimiterMiddleware();
    middleware(mockReq(), mockRes(), next);

    await vi.waitFor(() => expect(next).toHaveBeenCalled());
  });

  it('returns 429 when rate limit is exceeded', async () => {
    mockRateLimiter.consume.mockRejectedValue(new Error('rate limited'));
    const module = new SecurityModule({ redisClient: mockRedis as any });
    const res = mockRes();
    const middleware = module.rateLimiterMiddleware();
    middleware(mockReq(), res, next);

    await vi.waitFor(() => expect(res.status).toHaveBeenCalledWith(429));
    expect(res.send).toHaveBeenCalledWith('Too many Requests');
    expect(next).not.toHaveBeenCalled();
  });

  it('calls next() immediately when rate limiter is disabled', () => {
    const module = new SecurityModule({
      redisClient: mockRedis as any,
      rateLimiterEnabled: false,
    });
    const middleware = module.rateLimiterMiddleware();
    middleware(mockReq(), mockRes(), next);

    expect(next).toHaveBeenCalled();
    expect(mockRateLimiter.consume).not.toHaveBeenCalled();
  });
});


describe('helmetMiddleware', () => {
  it('returns a passthrough middleware when helmet is disabled', () => {
    const module = new SecurityModule({
      redisClient: mockRedis as any,
      helmetEnabled: false,
    });
    const middleware = module.helmetMiddleware();
    middleware(mockReq(), mockRes(), next);

    expect(next).toHaveBeenCalled();
  });

  it('returns a function when helmet is enabled', () => {
    const module = new SecurityModule({ redisClient: mockRedis as any });
    const middleware = module.helmetMiddleware();

    expect(typeof middleware).toBe('function');
  });
});
