import { describe, it, expect, vi, beforeEach } from 'vitest';
import { createIdentityEngine } from '../../oauth/brain/identityEngine';
import { identityPolicy } from '../../oauth/brain/identityPolicy';


const mockAdapter = {
  findUserByEmail: vi.fn(),
  findUserByProvider: vi.fn(),
  createUser: vi.fn(),
  linkProvider: vi.fn(),
};

const mockTokenService = {
  signAccessToken: vi.fn().mockReturnValue('mock-access-token'),
  generateRefreshToken: vi.fn().mockResolvedValue('mock-refresh-token'),
};

const mockUser = {
  id: 'user-123',
  email: 'test@example.com',
  providers: [{ provider: 'google', providerId: 'google-456' }],
};

const baseProfile = {
  email: 'test@example.com',
  provider: 'google',
  providerId: 'google-456',
  email_verified: true,
};

beforeEach(() => {
  vi.clearAllMocks();
});

describe('createIdentityEngine', () => {
  let engine: ReturnType<typeof createIdentityEngine>;

  beforeEach(() => {
    engine = createIdentityEngine(mockAdapter, mockTokenService);
  });

  
  describe('missing email guard', () => {
    it('throws when profile has no email', async () => {
      await expect(
        engine.resolveOAuth({
          profile: { ...baseProfile, email: '' },
          mode: 'login',
        })
      ).rejects.toThrow('OAuth profile missing email');
    });
  });


  describe('existing provider login', () => {
    it('returns EXISTING_PROVIDER_LOGIN when provider is already registered', async () => {
      mockAdapter.findUserByProvider.mockResolvedValue(mockUser);

      const result = await engine.resolveOAuth({
        profile: baseProfile,
        mode: 'login',
      });

      expect(result.type).toBe('EXISTING_PROVIDER_LOGIN');
      expect(result.user).toEqual(mockUser);
      expect(result.accessToken).toBe('mock-access-token');
      expect(result.refreshToken).toBe('mock-refresh-token');
      expect(mockTokenService.signAccessToken).toHaveBeenCalledWith({
        userId: mockUser.id,
        email: mockUser.email,
      });
    });

    it('does not call createUser or linkProvider for existing provider', async () => {
      mockAdapter.findUserByProvider.mockResolvedValue(mockUser);

      await engine.resolveOAuth({ profile: baseProfile, mode: 'login' });

      expect(mockAdapter.createUser).not.toHaveBeenCalled();
      expect(mockAdapter.linkProvider).not.toHaveBeenCalled();
    });
  });

  
  describe('link mode', () => {
    beforeEach(() => {
      mockAdapter.findUserByProvider.mockResolvedValue(null);
    });

    it('returns INVALID_LINK_REQUEST when userId is missing', async () => {
      const result = await engine.resolveOAuth({
        profile: baseProfile,
        mode: 'link',
        userId: undefined,
      });

      expect(result.type).toBe('INVALID_LINK_REQUEST');
      expect(result.message).toMatch(/missing authenticated user/i);
      expect(mockAdapter.linkProvider).not.toHaveBeenCalled();
    });

    it('links provider and returns LINK_PROVIDER on success', async () => {
      mockAdapter.linkProvider.mockResolvedValue(undefined);
      mockAdapter.findUserByEmail.mockResolvedValue(mockUser);

      const result = await engine.resolveOAuth({
        profile: baseProfile,
        mode: 'link',
        userId: 'user-123',
      });

      expect(result.type).toBe('LINK_PROVIDER');
      expect(result.user).toEqual(mockUser);
      expect(result.success).toBe(true);
      expect(mockAdapter.linkProvider).toHaveBeenCalledWith(
        'user-123',
        'google',
        'google-456'
      );
    });

    it('falls back to findUserByProvider when findUserByEmail returns null after link', async () => {
      mockAdapter.linkProvider.mockResolvedValue(undefined);
      mockAdapter.findUserByEmail.mockResolvedValue(null);
      mockAdapter.findUserByProvider.mockResolvedValueOnce(null) // initial check
                                     .mockResolvedValueOnce(mockUser); // fallback

      const result = await engine.resolveOAuth({
        profile: baseProfile,
        mode: 'link',
        userId: 'user-123',
      });

      expect(result.type).toBe('LINK_PROVIDER');
      expect(result.user).toEqual(mockUser);
    });

    it('throws LINK_PROVIDER_user resolution failed when both lookups return null', async () => {
      mockAdapter.linkProvider.mockResolvedValue(undefined);
      mockAdapter.findUserByEmail.mockResolvedValue(null);
      mockAdapter.findUserByProvider.mockResolvedValue(null);

      await expect(
        engine.resolveOAuth({
          profile: baseProfile,
          mode: 'link',
          userId: 'user-123',
        })
      ).rejects.toThrow('LINK_PROVIDER: user resolution failed');
    });
  });

  
  describe('existing user found by email', () => {
    beforeEach(() => {
      mockAdapter.findUserByProvider.mockResolvedValue(null);
      mockAdapter.findUserByEmail.mockResolvedValue(mockUser);
    });

    it('returns EXISTING_PROVIDER_LOGIN when auto-link is permitted', async () => {
      vi.spyOn(identityPolicy, 'autoLinkOnVerifiedEmailMatch', 'get').mockReturnValue(true);

      const result = await engine.resolveOAuth({
        profile: { ...baseProfile, email_verified: true },
        mode: 'login',
      });

      expect(result.type).toBe('EXISTING_PROVIDER_LOGIN');
      expect(result.user).toEqual(mockUser);
      expect(result.accessToken).toBe('mock-access-token');
    });

    it('returns LINK_REQUIRED when email is unverified and policy forbids auto-link', async () => {
      vi.spyOn(identityPolicy, 'autoLinkOnVerifiedEmailMatch', 'get').mockReturnValue(true);
      vi.spyOn(identityPolicy, 'allowUnverifiedAutoLink', 'get').mockReturnValue(false);

      const result = await engine.resolveOAuth({
        profile: { ...baseProfile, email_verified: false },
        mode: 'login',
      });

      expect(result.type).toBe('LINK_REQUIRED');
      expect(result.email).toBe(baseProfile.email);
      expect(result.provider).toBe(baseProfile.provider);
    });

    it('accepts email_verified as the string "true"', async () => {
      vi.spyOn(identityPolicy, 'autoLinkOnVerifiedEmailMatch', 'get').mockReturnValue(true);

      const result = await engine.resolveOAuth({
        profile: { ...baseProfile, email_verified: 'true' },
        mode: 'login',
      });

      expect(result.type).toBe('EXISTING_PROVIDER_LOGIN');
    });

    it('returns LINK_REQUIRED when verified but policy disables auto-link', async () => {
      vi.spyOn(identityPolicy, 'autoLinkOnVerifiedEmailMatch', 'get').mockReturnValue(false);
      vi.spyOn(identityPolicy, 'allowUnverifiedAutoLink', 'get').mockReturnValue(false);

      const result = await engine.resolveOAuth({
        profile: { ...baseProfile, email_verified: true },
        mode: 'login',
      });

      expect(result.type).toBe('LINK_REQUIRED');
    });
  });

  
  describe('new user creation', () => {
    beforeEach(() => {
      mockAdapter.findUserByProvider.mockResolvedValue(null);
      mockAdapter.findUserByEmail.mockResolvedValue(null);
      mockAdapter.createUser.mockResolvedValue(mockUser);
    });

    it('returns NEW_USER_CREATION for a brand new user', async () => {
      const result = await engine.resolveOAuth({
        profile: baseProfile,
        mode: 'login',
      });

      expect(result.type).toBe('NEW_USER_CREATION');
      expect(result.user).toEqual(mockUser);
      expect(result.accessToken).toBe('mock-access-token');
      expect(result.refreshToken).toBe('mock-refresh-token');
    });

    it('calls createUser with correct args', async () => {
      await engine.resolveOAuth({ profile: baseProfile, mode: 'login' });

      expect(mockAdapter.createUser).toHaveBeenCalledWith({
        email: baseProfile.email,
        provider: baseProfile.provider,
        providerId: baseProfile.providerId,
      });
    });

    it('signs tokens with the new user payload', async () => {
      await engine.resolveOAuth({ profile: baseProfile, mode: 'login' });

      expect(mockTokenService.signAccessToken).toHaveBeenCalledWith({
        userId: mockUser.id,
        email: mockUser.email,
      });
      expect(mockTokenService.generateRefreshToken).toHaveBeenCalledWith({
        userId: mockUser.id,
        email: mockUser.email,
      });
    });
  });
});
