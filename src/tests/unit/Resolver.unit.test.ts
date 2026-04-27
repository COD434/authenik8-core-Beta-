import { describe, it, expect, vi, beforeEach } from 'vitest';
import { resolveIdentity } from '../../oauth/brain/identityResolver';
import { identityPolicy } from '../../oauth/brain/identityPolicy';
import type { Provider } from '../../oauth/userStore';
import type { OAuthProfile } from '../../oauth/types';

vi.mock('../../oauth/userStore', () => ({
  findUserByEmail: vi.fn(),
  findUserByProvider: vi.fn(),
  createUser: vi.fn(),
  linkProvider: vi.fn(),
}));

import {
  findUserByEmail,
  findUserByProvider,
  createUser,
  linkProvider,
} from '../../oauth/userStore';

const mockUser = {
  id: 'user-123',
  email: 'test@example.com',
  providers: [{ provider: 'google' as Provider, providerId: 'google-456' }],
};

const mockProfile:OAuthProfile = {
  email: 'test@example.com',
  provider: 'google',
  providerId: 'google-456',
  email_verified: true,
};

beforeEach(() => {
  vi.clearAllMocks();
});

describe('resolveIdentity', () => {

  
  describe('when provider is already registered', () => {
    it('returns the existing user without touching email lookup', async () => {
      vi.mocked(findUserByProvider).mockResolvedValue(mockUser);

      const result = await resolveIdentity(mockProfile);

      expect(result).toEqual(mockUser);
      expect(findUserByEmail).not.toHaveBeenCalled();
      expect(createUser).not.toHaveBeenCalled();
      expect(linkProvider).not.toHaveBeenCalled();
    });
  });

  
  describe('when no existing user is found', () => {
    it('creates and returns a new user', async () => {
      const newUser = { ...mockUser, id: 'user-new' };
      vi.mocked(findUserByProvider).mockResolvedValue(undefined);
      vi.mocked(findUserByEmail).mockResolvedValue(undefined);
      vi.mocked(createUser).mockResolvedValue(newUser);

      const result = await resolveIdentity(mockProfile);

      expect(createUser).toHaveBeenCalledWith({
        email: mockProfile.email,
        provider: mockProfile.provider,
        providerId: mockProfile.providerId,
      });
      expect(result).toEqual(newUser);
    });

    it('does not call linkProvider when creating a new user', async () => {
      vi.mocked(findUserByProvider).mockResolvedValue(undefined);
      vi.mocked(findUserByEmail).mockResolvedValue(undefined);
      vi.mocked(createUser).mockResolvedValue(mockUser);

      await resolveIdentity(mockProfile);

      expect(linkProvider).not.toHaveBeenCalled();
    });
  });

  
  describe('when user exists by email and auto-link is enabled', () => {
    beforeEach(() => {
      vi.mocked(findUserByProvider).mockResolvedValue(undefined);
      vi.mocked(findUserByEmail).mockResolvedValue(mockUser);
      vi.mocked(linkProvider).mockResolvedValue(undefined);
      identityPolicy.autoLinkOnVerifiedEmailMatch = true;
    });

    it('links the provider and returns the existing user', async () => {
      const result = await resolveIdentity(mockProfile);

      expect(linkProvider).toHaveBeenCalledWith(
        mockUser.id,
        mockProfile.provider,
        mockProfile.providerId
      );
      expect(result).toEqual(mockUser);
      expect(createUser).not.toHaveBeenCalled();
    });
  });


  describe('when user exists by email but auto-link is disabled', () => {
    beforeEach(() => {
      vi.mocked(findUserByProvider).mockResolvedValue(undefined);
      vi.mocked(findUserByEmail).mockResolvedValue(mockUser);
      identityPolicy.autoLinkOnVerifiedEmailMatch = false;
    });

    it('returns an IDENTITY_CONFLICT result', async () => {
      const result = await resolveIdentity(mockProfile);

      expect(result).toEqual({
        type: 'IDENTITY_CONFLICT',
        user: mockUser,
        message: 'Account exists. Explicit linking required.',
      });
    });

    it('does not call linkProvider or createUser', async () => {
      await resolveIdentity(mockProfile);

      expect(linkProvider).not.toHaveBeenCalled();
      expect(createUser).not.toHaveBeenCalled();
    });
  });
});
