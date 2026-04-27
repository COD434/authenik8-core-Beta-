import { describe, it, expect, vi, beforeEach } from 'vitest';
import { JWTService } from '../../auth/jwtAuth';
import type { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';

const SECRET = 'test-secret';

const mockRedis = {
  set: vi.fn().mockResolvedValue('OK'),
  get: vi.fn(),
};

const mockReq = (overrides: Partial<Request> = {}) =>
  ({
    headers: {},
    cookies: {},
    ...overrides,
  }) as unknown as Request;

const mockRes = () => {
  const res = {
    status: vi.fn().mockReturnThis(),
    json: vi.fn().mockReturnThis(),
  };
  return res as unknown as Response;
};

const next = vi.fn() as NextFunction;

beforeEach(() => {
  vi.clearAllMocks();
});


describe('signToken', () => {
  it('returns a valid JWT string', () => {
    const service = new JWTService({ jwtSecret: SECRET });
    const token = service.signToken({ userId: 'u1', email: 'a@b.com' });

    expect(typeof token).toBe('string');
    expect(jwt.verify(token, SECRET)).toBeTruthy();
  });

  it('uses provided expiry', () => {
    const service = new JWTService({ jwtSecret: SECRET, expiry: '2h' });
    const token = service.signToken({ userId: 'u1', email: 'a@b.com' });
    const decoded = jwt.decode(token) as any;

    expect(decoded.exp - decoded.iat).toBe(7200);
  });

  it('defaults to 1h expiry when none provided', () => {
    const service = new JWTService({ jwtSecret: SECRET });
    const token = service.signToken({ userId: 'u1', email: 'a@b.com' });
    const decoded = jwt.decode(token) as any;

    expect(decoded.exp - decoded.iat).toBe(3600);
  });

  it('persists token to Redis when redisClient and userId are present', async () => {
    const service = new JWTService({ jwtSecret: SECRET, redisClient: mockRedis });
    const token = service.signToken({ userId: 'u1', email: 'a@b.com' });

    // persistSessionToken is fire-and-forget, wait a tick
    await new Promise((r) => setImmediate(r));

    expect(mockRedis.set).toHaveBeenCalledWith(
      'session:u1',
      token,
      'EX',
      expect.any(Number)
    );
  });

  it('does not persist token when redisClient is absent', async () => {
    const service = new JWTService({ jwtSecret: SECRET });
    service.signToken({ userId: 'u1', email: 'a@b.com' });

    await new Promise((r) => setImmediate(r));

    expect(mockRedis.set).not.toHaveBeenCalled();
  });

  it('does not persist token when payload has no userId', async () => {
    const service = new JWTService({ jwtSecret: SECRET, redisClient: mockRedis });
    service.signToken({ email: 'a@b.com' });

    await new Promise((r) => setImmediate(r));

    expect(mockRedis.set).not.toHaveBeenCalled();
  });

  it('logs error but does not throw when Redis.set fails', async () => {
    mockRedis.set.mockRejectedValueOnce(new Error('Redis down'));
    const spy = vi.spyOn(console, 'error').mockImplementation(() => {});
    const service = new JWTService({ jwtSecret: SECRET, redisClient: mockRedis });

    expect(() => service.signToken({ userId: 'u1', email: 'a@b.com' })).not.toThrow();

    await new Promise((r) => setImmediate(r));
    expect(spy).toHaveBeenCalledWith(
      'Failed to persist session token:',
      expect.any(Error)
    );
    spy.mockRestore();
  });
});


describe('guestToken', () => {
  it('returns a signed JWT with type=guest', () => {
    const service = new JWTService({ jwtSecret: SECRET, expiry: '1h' });
    const token = service.guestToken();
    const decoded = jwt.decode(token) as any;

    expect(decoded.type).toBe('guest');
    expect(decoded.id).toBeDefined();
    expect(decoded.createdAt).toBeDefined();
  });

  it('calls onGuestToken callback when provided', () => {
    const onGuestToken = vi.fn();
    const service = new JWTService({ jwtSecret: SECRET, expiry: '1h', onGuestToken });

    service.guestToken();

    expect(onGuestToken).toHaveBeenCalledTimes(1);
  });

  it('does not throw when onGuestToken is not provided', () => {
    const service = new JWTService({ jwtSecret: SECRET, expiry: '1h' });
    expect(() => service.guestToken()).not.toThrow();
  });
});


describe('verifyToken', () => {
  it('returns the decoded payload for a valid token', () => {
    const service = new JWTService({ jwtSecret: SECRET });
    const token = service.signToken({ userId: 'u1', email: 'a@b.com' });

    const result = service.verifyToken(token);

    expect(result?.userId).toBe('u1');
    expect(result?.email).toBe('a@b.com');
  });

  it('returns null for an invalid token', () => {
    const service = new JWTService({ jwtSecret: SECRET });

    expect(service.verifyToken('not-a-token')).toBeNull();
  });

  it('returns null for a token signed with a different secret', () => {
    const service = new JWTService({ jwtSecret: SECRET });
    const foreign = jwt.sign({ userId: 'u1' }, 'wrong-secret');

    expect(service.verifyToken(foreign)).toBeNull();
  });
});

describe('authenticateJWT', () => {
  it('returns 401 when no token is present', async () => {
    const service = new JWTService({ jwtSecret: SECRET });
    const res = mockRes();

    await service.authenticateJWT(mockReq(), res, next);

    expect(res.status).toHaveBeenCalledWith(401);
    expect(next).not.toHaveBeenCalled();
  });

  it('extracts token from Authorization Bearer header', async () => {
    const service = new JWTService({ jwtSecret: SECRET });
    const token = service.signToken({ userId: 'u1', email: 'a@b.com' });
    const res = mockRes();

    await service.authenticateJWT(
      mockReq({ headers: { authorization: `Bearer ${token}` } }),
      res,
      next
    );

    expect(next).toHaveBeenCalled();
  });

  it('extracts token from cookie', async () => {
    const service = new JWTService({ jwtSecret: SECRET });
    const token = service.signToken({ userId: 'u1', email: 'a@b.com' });
    const res = mockRes();

    await service.authenticateJWT(
      mockReq({ cookies: { token } }),
      res,
      next
    );

    expect(next).toHaveBeenCalled();
  });

  it('returns 403 when token is invalid', async () => {
    const service = new JWTService({ jwtSecret: SECRET });
    const res = mockRes();

    await service.authenticateJWT(
      mockReq({ headers: { authorization: 'Bearer bad-token' } }),
      res,
      next
    );

    expect(res.status).toHaveBeenCalledWith(403);
    expect(res.json).toHaveBeenCalledWith(
      expect.objectContaining({ message: 'invalid or expired token' })
    );
    expect(next).not.toHaveBeenCalled();
  });

  it('attaches decoded payload to req.user on success', async () => {
    const service = new JWTService({ jwtSecret: SECRET });
    const token = service.signToken({ userId: 'u1', email: 'a@b.com' });
    const req = mockReq({ cookies: { token } });
    const res = mockRes();

    await service.authenticateJWT(req, res, next);

    expect((req as any).user.userId).toBe('u1');
  });

  it('validates session token against Redis when redisClient is present', async () => {
    const token = jwt.sign({ userId: 'u1', email: 'a@b.com' }, SECRET, { expiresIn: '1h' });
    mockRedis.get.mockResolvedValue(token);

    const service = new JWTService({ jwtSecret: SECRET, redisClient: mockRedis });
    const res = mockRes();

    await service.authenticateJWT(
      mockReq({ cookies: { token } }),
      res,
      next
    );

    expect(mockRedis.get).toHaveBeenCalledWith('session:u1');
    expect(next).toHaveBeenCalled();
  });

  it('returns 403 when stored session token does not match', async () => {
    const token = jwt.sign({ userId: 'u1', email: 'a@b.com' }, SECRET, { expiresIn: '1h' });
    mockRedis.get.mockResolvedValue('different-token');

    const service = new JWTService({ jwtSecret: SECRET, redisClient: mockRedis });
    const res = mockRes();

    await service.authenticateJWT(
      mockReq({ cookies: { token } }),
      res,
      next
    );

    expect(res.status).toHaveBeenCalledWith(403);
    expect(res.json).toHaveBeenCalledWith(
      expect.objectContaining({ message: 'invalid session' })
    );
    expect(next).not.toHaveBeenCalled();
  });

  it('skips Redis check when decoded token has no userId', async () => {
    const token = jwt.sign({ email: 'a@b.com' }, SECRET, { expiresIn: '1h' });

    const service = new JWTService({ jwtSecret: SECRET, redisClient: mockRedis });
    const res = mockRes();

    await service.authenticateJWT(
      mockReq({ cookies: { token } }),
      res,
      next
    );

    expect(mockRedis.get).not.toHaveBeenCalled();
    expect(next).toHaveBeenCalled();
  });
});
