import { describe, it, expect, vi, beforeEach } from 'vitest';
import { createGoogleProvider } from '../../oauth/providers/google';
import type { Request, Response } from 'express';
import type { Provider } from '../../oauth/types';

//vi.mock('google-auth-library', () => {
  //const mockGetPayload = vi.fn();
  //const mockVerifyIdToken = vi.fn().mockResolvedValue({ getPayload: mockGetPayload });
  //const MockOAuth2Client = vi.fn(() => ({ verifyIdToken: mockVerifyIdToken }));
  //return { OAuth2Client: MockOAuth2Client, mockGetPayload, mockVerifyIdToken };
//});

//import { mockGetPayload, mockVerifyIdToken } from 'google-auth-library';
const { mockGetPayload, mockVerifyIdToken } = vi.hoisted(() => {
  const mockGetPayload = vi.fn();
  const mockVerifyIdToken = vi.fn().mockResolvedValue({ getPayload: mockGetPayload });
  return { mockGetPayload, mockVerifyIdToken };
});

vi.mock('google-auth-library', () => ({
  OAuth2Client: vi.fn(function () {
    return { verifyIdToken: mockVerifyIdToken };
  }),
}));
const mockStateStore = {
  set: vi.fn().mockResolvedValue(undefined),
  get: vi.fn(),
  del: vi.fn().mockResolvedValue(undefined),
};

const mockIdentityEngine = { resolveOAuth: vi.fn() };

const mockConfig = {
  clientId: 'google-client-id',
  clientSecret: 'google-client-secret',
  redirectUri: 'https://myapp.com/auth/google/callback',
};

const mockReq = (overrides: Partial<Request> = {}) =>
  ({
    query: {},
    path: '/auth/google',
    user: null,
    ...overrides,
  }) as unknown as Request;

const mockRes = () => {
  const res = {
    redirect: vi.fn(),
    status: vi.fn().mockReturnThis(),
    json: vi.fn().mockReturnThis(),
  };
  return res as unknown as Response;
};

function makeStoredState(overrides = {}) {
  return { userId: null, mode: 'login' as const, ...overrides };
}

const validPayload = {
  email: 'dev@example.com',
  name: 'Dev User',
  sub: 'google-sub-999',
  email_verified: true,
  iss: 'https://accounts.google.com',
};

function mockFetchSequence(...responses: Array<{ ok?: boolean; text?: string; json?: any }>) {
  let call = 0;
  vi.stubGlobal(
    'fetch',
    vi.fn(async () => {
      const r = responses[call++];
      if (!r) throw new Error('mockFetchSequence: unexpected fetch call');
      return {
        ok: r.ok ?? true,
        text: async () => r.text ?? '',
        json: async () => r.json ?? {},
      };
    })
  );
}
//let mockGetPayload: ReturnType<typeof vi.fn>;
//let mockVerifyIdToken: ReturnType<typeof vi.fn>;

//beforeAll(async () => {
	//const mocks = (await import('google-auth-library')) as any;
  //mockGetPayload = mocks.mockGetPayload;
  //mockVerifyIdToken = mocks.mockVerifyIdToken;
//});

beforeEach(() => {
  vi.clearAllMocks();
  vi.unstubAllGlobals();
});

describe('createGoogleProvider', () => {
  let provider: ReturnType<typeof createGoogleProvider>;

  beforeEach(() => {
    provider = createGoogleProvider(mockConfig, mockStateStore as any, mockIdentityEngine as any);
  });

  // ─── redirect ──────────────────────────────────────────────────────────
  describe('redirect', () => {
    it('stores state in Redis and redirects to Google', async () => {
      const req = mockReq();
      const res = mockRes();

      await provider.redirect(req, res);

      expect(mockStateStore.set).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({ mode: 'login' }),
        300
      );
      expect(res.redirect).toHaveBeenCalledWith(
        expect.stringContaining('https://accounts.google.com/o/oauth2/v2/auth')
      );
    });

    it('includes required OAuth params in the redirect URL', async () => {
      const req = mockReq();
      const res = mockRes();

      await provider.redirect(req, res);

      const url = new URL((res.redirect as any).mock.calls[0][0]);
      expect(url.searchParams.get('client_id')).toBe(mockConfig.clientId);
      expect(url.searchParams.get('redirect_uri')).toBe(mockConfig.redirectUri);
      expect(url.searchParams.get('response_type')).toBe('code');
      expect(url.searchParams.get('scope')).toBe('openid email profile');
      expect(url.searchParams.get('access_type')).toBe('offline');
      expect(url.searchParams.get('prompt')).toBe('consent');
      expect(url.searchParams.get('state')).toBeTruthy();
    });

    it('sets mode=link when path contains "link"', async () => {
      const req = mockReq({ path: '/auth/google/link' });
      const res = mockRes();

      await provider.redirect(req, res);

      expect(mockStateStore.set).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({ mode: 'link' }),
        300
      );
    });

    it('stores userId from req.user in Redis state', async () => {
      const req = mockReq({ user: { userId: 'user-123' } as any });
      const res = mockRes();

      await provider.redirect(req, res);

      expect(mockStateStore.set).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({ userId: 'user-123' }),
        300
      );
    });

    it('returns 500 when Redis throws', async () => {
      mockStateStore.set.mockRejectedValueOnce(new Error('State store down'));
      const req = mockReq();
      const res = mockRes();

      await provider.redirect(req, res);

      expect(res.status).toHaveBeenCalledWith(500);
      expect(res.json).toHaveBeenCalledWith({ error: 'OAuth redirect failed' });
      expect(res.redirect).not.toHaveBeenCalled();
    });
  });

  // ─── handleCallback ────────────────────────────────────────────────────
  describe('handleCallback', () => {
    it('throws when state is missing', async () => {
      const req = mockReq({ query: { code: 'abc' } });
      await expect(provider.handleCallback(req)).rejects.toThrow('OAuthError:Missing state');
    });

    it('throws when state is not found in Redis', async () => {
      mockStateStore.get.mockResolvedValue(null);
      const req = mockReq({ query: { code: 'abc', state: 'stale' } });
      await expect(provider.handleCallback(req)).rejects.toThrow('OAuthError:Invalid or expired state');
    });

    it('throws when code is missing', async () => {
      mockStateStore.get.mockResolvedValue(makeStoredState());
      const req = mockReq({ query: { state: 'valid-state' } });
      await expect(provider.handleCallback(req)).rejects.toThrow('OauthError:Missing authorization code');
    });

    it('throws when token exchange response is not ok', async () => {
      mockStateStore.get.mockResolvedValue(makeStoredState());
      mockFetchSequence({ ok: false, text: 'Bad Request' });

      const req = mockReq({ query: { code: 'mycode', state: 'valid-state' } });
      await expect(provider.handleCallback(req)).rejects.toThrow('OAuthError:Token exchange failed->Bad Request');
    });

    it('throws when no access_token is returned', async () => {
      mockStateStore.get.mockResolvedValue(makeStoredState());
      mockFetchSequence({ json: { id_token: 'some-id-token' } }); // missing access_token

      const req = mockReq({ query: { code: 'mycode', state: 'valid-state' } });
      await expect(provider.handleCallback(req)).rejects.toThrow('OAuthError:No access token returned');
    });

    it('throws when no id_token is returned', async () => {
      mockStateStore.get.mockResolvedValue(makeStoredState());
      mockFetchSequence({ json: { access_token: 'goog-token' } }); // missing id_token

      const req = mockReq({ query: { code: 'mycode', state: 'valid-state' } });
      await expect(provider.handleCallback(req)).rejects.toThrow('OAuthError:No id_token returned from Google');
    });

    it('throws when ID token payload is null', async () => {
      mockStateStore.get.mockResolvedValue(makeStoredState());
      mockFetchSequence({ json: { access_token: 'goog-token', id_token: 'id-tok' } });
      vi.mocked(mockGetPayload).mockReturnValue(null);

      const req = mockReq({ query: { code: 'mycode', state: 'valid-state' } });
      await expect(provider.handleCallback(req)).rejects.toThrow('OAuthError:Invalid ID token payload');
    });

    it('throws when email is absent from payload', async () => {
      mockStateStore.get.mockResolvedValue(makeStoredState());
      mockFetchSequence({ json: { access_token: 'goog-token', id_token: 'id-tok' } });
      vi.mocked(mockGetPayload).mockReturnValue({ ...validPayload, email: undefined });

      const req = mockReq({ query: { code: 'mycode', state: 'valid-state' } });
      await expect(provider.handleCallback(req)).rejects.toThrow('OAuthError:Email not present in ID token');
    });

    it('throws when email is not verified', async () => {
      mockStateStore.get.mockResolvedValue(makeStoredState());
      mockFetchSequence({ json: { access_token: 'goog-token', id_token: 'id-tok' } });
      vi.mocked(mockGetPayload).mockReturnValue({ ...validPayload, email_verified: false });

      const req = mockReq({ query: { code: 'mycode', state: 'valid-state' } });
      await expect(provider.handleCallback(req)).rejects.toThrow('OAuthError:Email not verified');
    });

    it('throws when issuer is invalid', async () => {
      mockStateStore.get.mockResolvedValue(makeStoredState());
      mockFetchSequence({ json: { access_token: 'goog-token', id_token: 'id-tok' } });
      vi.mocked(mockGetPayload).mockReturnValue({ ...validPayload, iss: 'https://evil.com' });

      const req = mockReq({ query: { code: 'mycode', state: 'valid-state' } });
      await expect(provider.handleCallback(req)).rejects.toThrow('OAuthError: Invalid issuer');
    });

    it('accepts the alternate accounts.google.com issuer', async () => {
      mockStateStore.get.mockResolvedValue(makeStoredState());
      mockFetchSequence({ json: { access_token: 'goog-token', id_token: 'id-tok' } });
      vi.mocked(mockGetPayload).mockReturnValue({ ...validPayload, iss: 'accounts.google.com' });

      const req = mockReq({ query: { code: 'mycode', state: 'valid-state' } });
      const result = await provider.handleCallback(req);

      expect(result.profile.provider).toBe('google');
    });

    it('returns correct profile, mode and userId on success', async () => {
      mockStateStore.get.mockResolvedValue(makeStoredState({ userId: 'user-123', mode: 'link' }));
      mockFetchSequence({ json: { access_token: 'goog-token', id_token: 'id-tok' } });
      vi.mocked(mockGetPayload).mockReturnValue(validPayload);

      const req = mockReq({ query: { code: 'mycode', state: 'valid-state' } });
      const result = await provider.handleCallback(req);

      expect(result.profile).toEqual({
        email: 'dev@example.com',
        name: 'Dev User',
        provider: 'google',
        providerId: 'google-sub-999',
        email_verified: true,
      });
      expect(result.mode).toBe('link');
      expect(result.userId).toBe('user-123');
    });

    it('deletes the state key from Redis after success', async () => {
      mockStateStore.get.mockResolvedValue(makeStoredState());
      mockFetchSequence({ json: { access_token: 'goog-token', id_token: 'id-tok' } });
      vi.mocked(mockGetPayload).mockReturnValue(validPayload);

      const req = mockReq({ query: { code: 'mycode', state: 'valid-state' } });
      await provider.handleCallback(req);

      expect(mockStateStore.del).toHaveBeenCalledWith('valid-state');
    });
  });
});
