import { describe, it, expect, vi, beforeEach } from 'vitest';
import { RedisTokenStore } from '../../storage/RedisTokenStore';


const mockRedis = {
  set: vi.fn().mockResolvedValue('OK'),
  get: vi.fn().mockResolvedValue(null),
  del: vi.fn().mockResolvedValue(1),
  exists: vi.fn().mockResolvedValue(0),
  incr: vi.fn().mockResolvedValue(1),
  expire: vi.fn().mockResolvedValue(1),
  eval: vi.fn().mockResolvedValue(1),
};

beforeEach(() => {
  vi.clearAllMocks();
});


function makeStore(debug = false) {
  return new RedisTokenStore(mockRedis as any, debug);
}

const PREFIX = 'auth:v1';


describe('storeRefreshToken', () => {
  it('stores token under auth:v1:refresh:<userId>', async () => {
    const store = makeStore();
    await store.storeRefreshToken('tok-abc', 'user-1', 3600);

    expect(mockRedis.set).toHaveBeenCalledWith(
      `${PREFIX}:refresh:user-1`,
      'tok-abc',
      'EX',
      3600
    );
  });
});


describe('getRefreshToken', () => {
  it('returns the stored value', async () => {
    mockRedis.get.mockResolvedValue('tok-abc');
    const store = makeStore();

    const result = await store.getRefreshToken('user-1');

    expect(result).toBe('tok-abc');
    expect(mockRedis.get).toHaveBeenCalledWith(`${PREFIX}:refresh:user-1`);
  });

  it('returns null when not found', async () => {
    mockRedis.get.mockResolvedValue(null);
    const store = makeStore();

    expect(await store.getRefreshToken('user-1')).toBeNull();
  });
});


describe('deleteRefreshToken', () => {
  it('deletes the correct key', async () => {
    const store = makeStore();
    await store.deleteRefreshToken('user-1');

    expect(mockRedis.del).toHaveBeenCalledWith(`${PREFIX}:refresh:user-1`);
  });
});


describe('del', () => {
  it('deletes an exact key', async () => {
    const store = makeStore();
    await store.del('refresh:user-1:session-1');

    expect(mockRedis.del).toHaveBeenCalledWith('refresh:user-1:session-1');
  });
});


describe('compareAndSet', () => {
  it('returns true when Redis updates the matching value', async () => {
    mockRedis.eval.mockResolvedValue(1);
    const store = makeStore();

    const result = await store.compareAndSet('my-key', 'old-value', 'new-value', 60);

    expect(result).toBe(true);
    expect(mockRedis.eval).toHaveBeenCalledWith(
      expect.any(String),
      1,
      'my-key',
      'old-value',
      'new-value',
      '60'
    );
  });

  it('returns false when Redis does not update the value', async () => {
    mockRedis.eval.mockResolvedValue(0);
    const store = makeStore();

    await expect(store.compareAndSet('my-key', 'old-value', 'new-value')).resolves.toBe(false);
  });
});


describe('blacklistToken', () => {
  it('sets blacklist key with correct TTL', async () => {
    const store = makeStore();
    await store.blacklistToken('user-1', 900);

    expect(mockRedis.set).toHaveBeenCalledWith(
      `${PREFIX}:blacklist:user-1`,
      '1',
      'EX',
      900
    );
  });
});


describe('isBlacklisted', () => {
  it('returns true when key exists', async () => {
    mockRedis.exists.mockResolvedValue(1);
    const store = makeStore();

    expect(await store.isBlacklisted('user-1')).toBe(true);
  });

  it('returns false when key does not exist', async () => {
    mockRedis.exists.mockResolvedValue(0);
    const store = makeStore();

    expect(await store.isBlacklisted('user-1')).toBe(false);
  });
});


describe('incrementRateLimit', () => {
  it('increments the rate limit key', async () => {
    mockRedis.incr.mockResolvedValue(1);
    const store = makeStore();

    const count = await store.incrementRateLimit('1.2.3.4', 60);

    expect(mockRedis.incr).toHaveBeenCalledWith(`${PREFIX}:rate:1.2.3.4`);
    expect(count).toBe(1);
  });

  it('sets expiry only on the first increment', async () => {
    mockRedis.incr.mockResolvedValue(1);
    const store = makeStore();
    await store.incrementRateLimit('1.2.3.4', 60);

    expect(mockRedis.expire).toHaveBeenCalledWith(`${PREFIX}:rate:1.2.3.4`, 60);
  });

  it('does not set expiry on subsequent increments', async () => {
    mockRedis.incr.mockResolvedValue(2);
    const store = makeStore();
    await store.incrementRateLimit('1.2.3.4', 60);

    expect(mockRedis.expire).not.toHaveBeenCalled();
  });
});


describe('whitelist', () => {
  it('addToWhitelist sets the correct key', async () => {
    const store = makeStore();
    await store.addToWhitelist('1.2.3.4');

    expect(mockRedis.set).toHaveBeenCalledWith(
      `${PREFIX}:whitelist:1.2.3.4`,
      '1'
    );
  });

  it('removeFromWhitelist deletes the correct key', async () => {
    const store = makeStore();
    await store.removeFromWhitelist('1.2.3.4');

    expect(mockRedis.del).toHaveBeenCalledWith(`${PREFIX}:whitelist:1.2.3.4`);
  });

  it('isWhitelisted returns true when key exists', async () => {
    mockRedis.exists.mockResolvedValue(1);
    const store = makeStore();

    expect(await store.isWhitelisted('1.2.3.4')).toBe(true);
  });

  it('isWhitelisted returns false when key does not exist', async () => {
    mockRedis.exists.mockResolvedValue(0);
    const store = makeStore();

    expect(await store.isWhitelisted('1.2.3.4')).toBe(false);
  });
});


describe('set', () => {
  it('calls redis.set with EX when expiry is provided', async () => {
const store = makeStore();
    await store.set('custom-key', 'val', 120);

    expect(mockRedis.set).toHaveBeenCalledWith('custom-key', 'val', 'EX', 120);
  });

  it('calls redis.set without EX when no expiry', async () => {
    const store = makeStore();
    await store.set('custom-key', 'val');

    expect(mockRedis.set).toHaveBeenCalledWith('custom-key', 'val');
  });
});

describe('get', () => {
  it('returns value from redis', async () => {
    mockRedis.get.mockResolvedValue('stored-val');
    const store = makeStore();

    expect(await store.get('custom-key')).toBe('stored-val');
  });

  it('returns null when key is missing', async () => {
    mockRedis.get.mockResolvedValue(null);
    const store = makeStore();

    expect(await store.get('missing-key')).toBeNull();
  });
});
