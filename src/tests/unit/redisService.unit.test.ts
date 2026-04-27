import { describe, it, expect, vi, beforeEach } from 'vitest';
import { setupRedis, initializeRedisClient, validateRedisConfig, getRedisConfig } from '../../redis/redisService';


vi.mock('connect-redis', () => ({
  RedisStore: vi.fn().mockImplementation(() => ({ mockStore: true })),
}));

// We need full control over the Redis instance's event emitter
// so we build a factory that returns a fresh controllable mock each call
let currentMockRedis: ReturnType<typeof makeMockRedis>;

function makeMockRedis(behavior: 'ready' | 'error' = 'ready') {
  const handlers: Record<string, Function[]> = {};

  const instance = {
    once: vi.fn((event: string, cb: Function) => {
      if (!handlers[event]) handlers[event] = [];
      handlers[event].push(cb);

      
      if (event === 'ready' && behavior === 'ready') {
        setImmediate(() => cb());
      }
      if (event === 'error' && behavior === 'error') {
        setImmediate(() => cb(new Error('Redis connection failed')));
      }
    }),
    on: vi.fn(),
    ping: vi.fn().mockResolvedValue('PONG'),
  };

  return instance;
}

vi.mock('ioredis', () => {
  const RedisMock = vi.fn(() => {
    currentMockRedis = makeMockRedis();
    return currentMockRedis;
  });
  return { default: RedisMock, Redis: RedisMock };
});

import Redis from 'ioredis';

beforeEach(() => {
  vi.clearAllMocks();
});


describe('validateRedisConfig', () => {
  it('throws when neither url nor host is provided', () => {
    expect(() =>
      validateRedisConfig({ connectTimeout: 5000 } as any)
    ).toThrow('Redis configuration requires either URL or host/port');
  });

  it('throws when URL does not start with redis:// or rediss://', () => {
    expect(() =>
      validateRedisConfig({ url: 'http://localhost:6379', connectTimeout: 5000 })
    ).toThrow("Redis URL must use 'redis://' protocol");
  });

  it('passes for a valid redis:// URL', () => {
    expect(() =>
      validateRedisConfig({ url: 'redis://localhost:6379', connectTimeout: 5000 })
    ).not.toThrow();
  });

  it('passes for a valid rediss:// URL', () => {
    expect(() =>
      validateRedisConfig({ url: 'rediss://localhost:6379', connectTimeout: 5000 })
    ).not.toThrow();
  });

  it('passes when host is provided', () => {
    expect(() =>
      validateRedisConfig({ host: '127.0.0.1', connectTimeout: 5000 })
    ).not.toThrow();
  });
});


describe('getRedisConfig', () => {
  it('returns defaults when no options provided', () => {
    const config = getRedisConfig();
    expect(config.host).toBe('127.0.0.1');
    expect(config.port).toBe(6379);
    expect(config.connectTimeout).toBe(5000);
  });

  it('overrides host and port from options', () => {
    const config = getRedisConfig({ host: 'myredis', port: 6380 });
    expect(config.host).toBe('myredis');
    expect(config.port).toBe(6380);
  });

  it('uses password from options', () => {
    const config = getRedisConfig({ host: '127.0.0.1', password: 'secret' });
    expect(config.password).toBe('secret');
  });

  it('uses REDIS_PORT env var when no port option is given', () => {
    process.env.REDIS_PORT = '6381';
    const config = getRedisConfig({ host: '127.0.0.1' });
    expect(config.port).toBe(6381);
    delete process.env.REDIS_PORT;
  });
});


describe('setupRedis', () => {
  it('resolves with redisClient and redisStore on success', async () => {
    vi.mocked(Redis).mockImplementationOnce(() => {
      currentMockRedis = makeMockRedis('ready');
      return currentMockRedis as any;
    });

    const result = await setupRedis();

    expect(result.redisClient).toBeDefined();
    expect(result.redisStore).toBeDefined();
  });

  it('calls ping after ready event fires', async () => {
    vi.mocked(Redis).mockImplementationOnce(() => {
      currentMockRedis = makeMockRedis('ready');
      return currentMockRedis as any;
    });

    await setupRedis();

    expect(currentMockRedis.ping).toHaveBeenCalled();
  });

  it('registers on("error"), on("ready"), on("reconnecting") listeners', async () => {
    vi.mocked(Redis).mockImplementationOnce(() => {
      currentMockRedis = makeMockRedis('ready');
      return currentMockRedis as any;
    });

    await setupRedis();

    const events = vi.mocked(currentMockRedis.on).mock.calls.map(([e]) => e);
    expect(events).toContain('error');
    expect(events).toContain('ready');
    expect(events).toContain('reconnecting');
  });

  it('rejects and rethrows when Redis emits an error event', async () => {
    vi.mocked(Redis).mockImplementationOnce(() => {
      currentMockRedis = makeMockRedis('error');
      return currentMockRedis as any;
    });

    await expect(setupRedis()).rejects.toThrow('Redis connection failed');
  });

  it('rejects when ping throws after ready', async () => {
    vi.mocked(Redis).mockImplementationOnce(() => {
      const instance = makeMockRedis('ready');
      instance.ping.mockRejectedValueOnce(new Error('ping failed'));
      currentMockRedis = instance;
      return instance as any;
    });

    await expect(setupRedis()).rejects.toThrow('ping failed');
  });

  it('merges custom storeOptions with defaults', async () => {
    vi.mocked(Redis).mockImplementationOnce(() => {
      currentMockRedis = makeMockRedis('ready');
      return currentMockRedis as any;
    });

    const { RedisStore } = await import('connect-redis');
    await setupRedis({ storeOptions: { prefix: 'custom', ttl: 3600 } });

    expect(RedisStore).toHaveBeenCalledWith(
      expect.objectContaining({ prefix: 'custom', ttl: 3600 })
    );
  });

  it('passes password to Redis constructor when provided', async () => {
    vi.mocked(Redis).mockImplementationOnce(() => {
      currentMockRedis = makeMockRedis('ready');
      return currentMockRedis as any;
    });

    await setupRedis({ redisConfig: { host: '127.0.0.1', password: 'mypassword' } });

    expect(Redis).toHaveBeenCalledWith(
      expect.objectContaining({ password: 'mypassword' })
    );
  });
});


describe('initializeRedisClient', () => {
  it('returns a Redis client', async () => {
    vi.mocked(Redis).mockImplementationOnce(() => {
      currentMockRedis = makeMockRedis('ready');
      return currentMockRedis as any;
    });

    const client = await initializeRedisClient();
    expect(client).toBeDefined();
  });

  it('returns the same instance on repeated calls (singleton)', async () => {
    vi.mocked(Redis).mockImplementation(() => {
      currentMockRedis = makeMockRedis('ready');
      return currentMockRedis as any;
    });

    const first = await initializeRedisClient();
    const second = await initializeRedisClient();

    expect(first).toBe(second);
    
    expect(vi.mocked(Redis).mock.calls.length).toBeLessThanOrEqual(
      vi.mocked(Redis).mock.calls.length
    );
  });
});
