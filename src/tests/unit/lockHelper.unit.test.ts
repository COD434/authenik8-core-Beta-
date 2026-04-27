import { describe, it, expect, vi, beforeEach } from 'vitest';
import { RedisLock } from '../../utility/lockHelper';

const mockRedis = {
  set: vi.fn(),
  eval: vi.fn().mockResolvedValue(1),
};

beforeEach(() => {
  vi.clearAllMocks();
});

describe('RedisLock', () => {
  let lock: RedisLock;

  beforeEach(() => {
    lock = new RedisLock(mockRedis);
  });

  describe('acquire', () => {
    it('returns a string value when lock is acquired', async () => {
      mockRedis.set.mockResolvedValue('OK');

      const result = await lock.acquire('my-lock');

      expect(result).toBeTypeOf('string');
      expect(result).not.toBeNull();
    });

    it('returns null when lock is already held', async () => {
      mockRedis.set.mockResolvedValue(null);

      const result = await lock.acquire('my-lock');

      expect(result).toBeNull();
    });

    it('calls redis.set with PX, ttl and NX options', async () => {
      mockRedis.set.mockResolvedValue('OK');

      await lock.acquire('my-lock', 3000);

      expect(mockRedis.set).toHaveBeenCalledWith(
        'my-lock',
        expect.any(String),
        'PX',
        3000,
        'NX'
      );
    });

    it('uses default ttl of 5000 when none provided', async () => {
      mockRedis.set.mockResolvedValue('OK');

      await lock.acquire('my-lock');

      expect(mockRedis.set).toHaveBeenCalledWith(
        'my-lock',
        expect.any(String),
        'PX',
        5000,
        'NX'
      );
    });

    it('returns a unique value on each acquisition', async () => {
      mockRedis.set.mockResolvedValue('OK');

      const a = await lock.acquire('lock-a');
      const b = await lock.acquire('lock-b');

      expect(a).not.toBe(b);
    });
  });

  describe('release', () => {
    it('calls redis.eval with the lua script, key and value', async () => {
      await lock.release('my-lock', 'lock-value-xyz');

      expect(mockRedis.eval).toHaveBeenCalledWith(
        expect.stringContaining('redis.call("GET"'),
        1,
        'my-lock',
        'lock-value-xyz'
      );
    });

    it('passes the correct number of keys (1) to eval', async () => {
      await lock.release('my-lock', 'lock-value-xyz');

      const [, numKeys] = mockRedis.eval.mock.calls[0];
      expect(numKeys).toBe(1);
    });

    it('resolves without throwing when Redis returns 0 (lock already gone)', async () => {
      mockRedis.eval.mockResolvedValue(0);

      await expect(lock.release('my-lock', 'stale-value')).resolves.toBeUndefined();
    });
  });
});
