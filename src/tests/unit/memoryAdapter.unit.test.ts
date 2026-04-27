import { describe, it, expect, beforeEach } from 'vitest';
import { memoryAdapter } from '../../oauth/adapters/memoryAdapter';

const mockEmail = 'test@example.com';
const mockProvider = 'google';
const mockProviderId = 'google-123';

beforeEach(() => {
  memoryAdapter.reset();
});

describe('findUserByEmail', () => {
  it('returns null when no users exist', async () => {
    const result = await memoryAdapter.findUserByEmail(mockEmail);
    expect(result).toBeNull();
  });

  it('returns the user when email matches', async () => {
    const created = await memoryAdapter.createUser({
      email: mockEmail,
      provider: mockProvider,
      providerId: mockProviderId,
    });

    const found = await memoryAdapter.findUserByEmail(mockEmail);
    expect(found).toEqual(created);
  });

  it('returns null when email does not match', async () => {
    await memoryAdapter.createUser({
      email: mockEmail,
      provider: mockProvider,
      providerId: mockProviderId,
    });

    const found = await memoryAdapter.findUserByEmail('other@example.com');
    expect(found).toBeNull();
  });
});

describe('findUserByProvider', () => {
  it('returns null when no users exist', async () => {
    const result = await memoryAdapter.findUserByProvider(mockProvider, mockProviderId);
    expect(result).toBeNull();
  });

  it('returns the user when provider and providerId match', async () => {
    const created = await memoryAdapter.createUser({
      email: mockEmail,
      provider: mockProvider,
      providerId: mockProviderId,
    });

    const found = await memoryAdapter.findUserByProvider(mockProvider, mockProviderId);
    expect(found).toEqual(created);
  });

  it('returns null when provider matches but providerId does not', async () => {
    await memoryAdapter.createUser({
      email: mockEmail,
      provider: mockProvider,
      providerId: mockProviderId,
    });

    const found = await memoryAdapter.findUserByProvider(mockProvider, 'wrong-id');
    expect(found).toBeNull();
  });

  it('returns null when providerId matches but provider does not', async () => {
    await memoryAdapter.createUser({
      email: mockEmail,
      provider: mockProvider,
      providerId: mockProviderId,
    });

    const found = await memoryAdapter.findUserByProvider('github', mockProviderId);
    expect(found).toBeNull();
  });
});

describe('createUser', () => {
  it('returns a user with a generated id', async () => {
    const user = await memoryAdapter.createUser({
      email: mockEmail,
      provider: mockProvider,
      providerId: mockProviderId,
    });

    expect(user.id).toBeDefined();
    expect(user.id).toBeTypeOf('string');
  });

  it('stores the correct email and provider', async () => {
    const user = await memoryAdapter.createUser({
      email: mockEmail,
      provider: mockProvider,
      providerId: mockProviderId,
    });

    expect(user.email).toBe(mockEmail);
    expect(user.providers).toEqual([{ provider: mockProvider, providerId: mockProviderId }]);
  });

  it('generates unique ids for different users', async () => {
    const a = await memoryAdapter.createUser({ email: 'a@example.com', provider: mockProvider, providerId: 'id-a' });
    const b = await memoryAdapter.createUser({ email: 'b@example.com', provider: mockProvider, providerId: 'id-b' });

    expect(a.id).not.toBe(b.id);
  });
});

describe('linkProvider', () => {
  it('throws if user does not exist', async () => {
    await expect(
      memoryAdapter.linkProvider('nonexistent-id', mockProvider, mockProviderId)
    ).rejects.toThrow('User not found: nonexistent-id');
  });

  it('appends the new provider to the user', async () => {
    const user = await memoryAdapter.createUser({
      email: mockEmail,
      provider: mockProvider,
      providerId: mockProviderId,
    });

    await memoryAdapter.linkProvider(user.id, 'github', 'github-456');

    const found = await memoryAdapter.findUserByEmail(mockEmail);
    expect(found?.providers).toHaveLength(2);
    expect(found?.providers).toContainEqual({ provider: 'github', providerId: 'github-456' });
  });

  it('allows finding user by the newly linked provider', async () => {
    const user = await memoryAdapter.createUser({
      email: mockEmail,
      provider: mockProvider,
      providerId: mockProviderId,
    });

    await memoryAdapter.linkProvider(user.id, 'github', 'github-456');

    const found = await memoryAdapter.findUserByProvider('github', 'github-456');
    expect(found?.id).toBe(user.id);
  });
});

describe('dump', () => {
  it('returns empty array when store is empty', () => {
    expect(memoryAdapter.dump()).toEqual([]);
  });

  it('returns all created users', async () => {
    await memoryAdapter.createUser({ email: 'a@example.com', provider: mockProvider, providerId: 'id-a' });
    await memoryAdapter.createUser({ email: 'b@example.com', provider: mockProvider, providerId: 'id-b' });

    expect(memoryAdapter.dump()).toHaveLength(2);
  });
});

describe('reset', () => {
  it('clears all users from the store', async () => {
    await memoryAdapter.createUser({ email: mockEmail, provider: mockProvider, providerId: mockProviderId });
    memoryAdapter.reset();

    expect(memoryAdapter.dump()).toHaveLength(0);
    expect(await memoryAdapter.findUserByEmail(mockEmail)).toBeNull();
  });
});
