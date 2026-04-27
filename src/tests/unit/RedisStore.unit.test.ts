import { describe, it, expect, vi, beforeEach } from 'vitest';
import { RedisTokenStore } from '../../storage/RedisTokenStore';

// ====================== MOCKS ======================
const mockRedis = {
  set: vi.fn().mockResolvedValue('OK'),
  get: vi.fn().mockResolvedValue(null),
  del: vi.fn().mockResolvedValue(1),
  exists: vi.fn().mockResolvedValue(0),
  incr: vi.fn().mockResolvedValue(1),
  expire: vi.fn().mockResolvedValue(1),
  getset: vi.fn().mockResolvedValue(null),
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
      'user-1',
      'EX',
      3600
    );
  });
});


describe('getRefreshToken', () => {
  it('returns the stored value', async () => {
    mockRedis.get.mockResolvedValue('user-1');
    const store = makeStore();

    const result = await store.getRefreshToken('user-1');

    expect(result).toBe('user-1');
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


describe('getset', () => {
  it('calls redis.getset and returns the previous value', async () => {
    mockRedis.getset.mockResolvedValue('old-value');
    const store = makeStore();

    const result = await store.getset('my-key', 'new-value');

    expect(mockRedis.getset).toHaveBeenCalledWith('my-key', 'new-value');
    expect(result).toBe('old-value');
  });

  it('sets expiry when provided', async () => {
    const store = makeStore();
    await store.getset('my-key', 'new-value', 60);

    expect(mockRedis.expire).toHaveBeenCalledWith('my-key', 60);
  });

  it('does not call expire when no expiry is given', async () => {
    const store = makeStore();
    await store.getset('my-key', 'new-value');

    expect(mockRedis.expire).not.toHaveBeenCalled();
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


describe('debug logging', () => {
  it('logs to console when debug=true', async () => {
    const spy = vi.spyOn(console, 'log').mockImplementation(() => {});
    const store = makeStore(true);
    await store.getRefreshToken('user-1');

    expect(spy).toHaveBeenCalled();
    spy.mockRestore();
  });

  it('redacts value for refresh keys in debug output', async () => {
    const spy = vi.spyOn(console, 'log').mockImplementation(() => {});
    const store = makeStore(true);
    await store.storeRefreshToken('tok', 'user-1', 3600);

    const logArg = spy.mock.calls[0][1];
    expect(logArg.value).toBe('<redacted>');
    spy.mockRestore();
  });

  it('does not log when debug=false', async () => {
    const spy = vi.spyOn(console, 'log').mockImplementation(() => {});
    const store = makeStore(false);
    await store.getRefreshToken('user-1');

    expect(spy).not.toHaveBeenCalled();
    spy.mockRestore();
  });
});
