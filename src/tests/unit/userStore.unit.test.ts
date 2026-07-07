import { describe, it, expect, vi, beforeEach } from 'vitest';
import crypto from 'crypto';
import { resetStore } from '../../oauth/userStore';

import {
  findUserByEmail,
  findUserByProvider,
  createUser,
  linkProvider,
} from '../../oauth/userStore';
import type { Provider } from '../../oauth/types';


vi.mock('crypto', () => ({
  default: {
    randomUUID: vi.fn(() => 'test-uuid-1234567890'),
  },
}));



describe('In-memory OAuth User Store', () => {
  const mockEmail = 'test@example.com';
  const mockGoogle: Provider = 'google';
  const mockGitHub: Provider = 'github';
  const mockProviderId = 'provider-abc123';

  beforeEach(() => {
    vi.clearAllMocks();
    vi.resetModules();
    resetStore();
  });

  describe('findUserByEmail', () => {
    it('returns undefined when user does not exist', async () => {
      const user = await findUserByEmail('nonexistent@example.com');
      expect(user).toBeUndefined();
    });

    it('returns the user when email matches', async () => {
      await createUser({
        email: mockEmail,
        provider: mockGoogle,
        providerId: mockProviderId,
      });

      const found = await findUserByEmail(mockEmail);
      expect(found).toBeDefined();
      expect(found?.email).toBe(mockEmail);
    });
  });

  describe('findUserByProvider', () => {
    it('returns undefined when no matching provider', async () => {
      const user = await findUserByProvider('github', 'unknown-999');
      expect(user).toBeUndefined();
    });

    it('finds user by provider + providerId', async () => {
      const created = await createUser({
        email: mockEmail,
        provider: mockGoogle,
        providerId: mockProviderId,
      });

      const found = await findUserByProvider(mockGoogle, mockProviderId);
      expect(found).toEqual(created);
    });
  });

  describe('createUser', () => {
    it('creates a new user with UUID, email and initial provider', async () => {
      const data = {
        email: mockEmail,
        provider: mockGoogle,
        providerId: mockProviderId,
      };

      const user = await createUser(data);

      expect(user.id).toBe('test-uuid-1234567890');
      expect(user.email).toBe(mockEmail);
      expect(user.role).toBeUndefined();
      expect(user.providers).toEqual([
        { provider: mockGoogle, providerId: mockProviderId },
      ]);
    });

    it('adds the user to the store', async () => {
      await createUser({
        email: mockEmail,
        provider: mockGoogle,
        providerId: mockProviderId,
      });

      const found = await findUserByEmail(mockEmail);
      expect(found).toBeDefined();
    });
  });

  describe('linkProvider', () => {

    it('throws when userId does not exist', async () => {
  await expect(
    linkProvider('non-existent-id', 'github', 'github-123')
  ).rejects.toThrow('User Not Found:,non-existent-id');
});

    it('adds a new provider if not already linked', async () => {
      const user = await createUser({
        email: mockEmail,
        provider: mockGoogle,
        providerId: mockProviderId,
      });

      await linkProvider(user.id, mockGitHub, 'github-xyz789');

      const updated = await findUserByEmail(mockEmail);
      expect(updated?.providers).toHaveLength(2);
      expect(updated?.providers).toContainEqual({
        provider: mockGitHub,
        providerId: 'github-xyz789',
      });
    });

    it('does not duplicate an already-linked provider', async () => {
      const user = await createUser({
        email: mockEmail,
        provider: mockGoogle,
        providerId: mockProviderId,
      });

      await linkProvider(user.id, mockGoogle, 'duplicate-id');

      const updated = await findUserByEmail(mockEmail);
      expect(updated?.providers).toHaveLength(1);
    });
  });
});
