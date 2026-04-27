import { describe, it, expect, vi, beforeEach } from 'vitest';
import { createGitHubProvider } from '../../oauth/providers/github';
import type { Request, Response } from 'express';


const mockRedis = {
  setex: vi.fn().mockResolvedValue('OK'),
  get: vi.fn(),
  del: vi.fn().mockResolvedValue(1),
};

const mockIdentityEngine = {
  resolveOAuth: vi.fn(),
};

const mockConfig = {
  clientId: 'gh-client-id',
  clientSecret: 'gh-client-secret',
  redirectUri: 'https://myapp.com/auth/github/callback',
};

const mockReq = (overrides = {}) =>
  ({
    query: {},
    user: null,
    ...overrides,
  }) as unknown as Request;

const mockRes = () => {
  const res = {
    headersSent: false,
    redirect: vi.fn(),
  };
  return res as unknown as Response;
};


function makeStoredState(overrides = {}) {
  return JSON.stringify({ userId: null, mode: 'login', ...overrides });
}

function mockFetchSequence(...responses: Array<{ ok?: boolean; text?:string; json: any }>) {
  let call = 0;
  vi.stubGlobal(
    'fetch',
    vi.fn(async () => {
      const r = responses[call++];
      if (!r) throw new Error('mockFetchSequence: unexpected fetch call');
      return {
        ok: r.ok ?? true,
	text: async () => r.text ?? '',
        json: async () => r.json ?? {}
		
      };
    })
  );
}

beforeEach(() => {
  vi.clearAllMocks();
  vi.unstubAllGlobals();
});

describe('createGitHubProvider', () => {
  let provider: ReturnType<typeof createGitHubProvider>;

  beforeEach(() => {
    provider = createGitHubProvider(
      mockConfig,
      mockRedis as any,
      mockIdentityEngine as any
    );
  });

  
  describe('redirect', () => {
    it('stores state in Redis and redirects to GitHub', async () => {
      const req = mockReq();
      const res = mockRes();

      await provider.redirect(req, res);

      expect(mockRedis.setex).toHaveBeenCalledWith(
        expect.stringMatching(/^oauth:state:/),
        300,
        expect.stringContaining('"mode":"login"')
      );
      expect(res.redirect).toHaveBeenCalledWith(
        expect.stringContaining('https://github.com/login/oauth/authorize')
      );
    });

    it('includes clientId, redirectUri, scope and state in the redirect URL', async () => {
      const req = mockReq();
      const res = mockRes();

      await provider.redirect(req, res);

      const url = new URL((res.redirect as any).mock.calls[0][0]);
      expect(url.searchParams.get('client_id')).toBe(mockConfig.clientId);
      expect(url.searchParams.get('redirect_uri')).toBe(mockConfig.redirectUri);
      expect(url.searchParams.get('scope')).toBe('read:user user:email');
      expect(url.searchParams.get('state')).toBeTruthy();
    });

    it('stores userId from req.user in Redis state', async () => {
      const req = mockReq({ user: { userId: 'user-123' } });
      const res = mockRes();

      await provider.redirect(req, res, 'link');

      expect(mockRedis.setex).toHaveBeenCalledWith(
        expect.any(String),
        300,
        expect.stringContaining('"userId":"user-123"')
      );
    });

    it('stores mode=link when link mode is passed', async () => {
      const req = mockReq();
      const res = mockRes();

      await provider.redirect(req, res, 'link');

      expect(mockRedis.setex).toHaveBeenCalledWith(
        expect.any(String),
        300,
        expect.stringContaining('"mode":"link"')
      );
    });

    it('skips redirect when headers are already sent', async () => {
      const req = mockReq();
      const res = { ...mockRes(), headersSent: true };

      await provider.redirect(req, res as unknown as Response);

      expect(res.redirect).not.toHaveBeenCalled();
      expect(mockRedis.setex).not.toHaveBeenCalled();
    });
  });

  
  describe('handleCallback', () => {
    it('throws when state is missing from query', async () => {
      const req = mockReq({ query: { code: 'abc' } });

      await expect(provider.handleCallback(req)).rejects.toThrow(
        'OAuthError:Missing state'
      );
    });

    it('throws when state is not found in Redis', async () => {
      mockRedis.get.mockResolvedValue(null);
      const req = mockReq({ query: { code: 'abc', state: 'bad-state' } });

      await expect(provider.handleCallback(req)).rejects.toThrow(
        'OAuthError:Invalid or expired state'
      );
    });

    it('throws when code is missing from query', async () => {
      mockRedis.get.mockResolvedValue(makeStoredState());
      const req = mockReq({ query: { state: 'valid-state' } });

      await expect(provider.handleCallback(req)).rejects.toThrow(
        'OAuthError: Missing code'
      );
    });

    it('throws when GitHub returns no access token', async () => {
      mockRedis.get.mockResolvedValue(makeStoredState());
      mockFetchSequence({ json: {} }); // token exchange returns empty

      const req = mockReq({ query: { code: 'mycode', state: 'valid-state' } });

      await expect(provider.handleCallback(req)).rejects.toThrow(
        'OAuthError: No access token from Github'
      );
    });

    it('throws when GitHub user fetch fails', async () => {
      mockRedis.get.mockResolvedValue(makeStoredState());
      mockFetchSequence(
        { json: { access_token: 'gh-token' } }, 
        { ok: false, json: {} }                  
      );

      const req = mockReq({ query: { code: 'mycode', state: 'valid-state' } });

      await expect(provider.handleCallback(req)).rejects.toThrow(
        'OAuthError: Failed to fetch GitHub user'
      );
    });

    it('throws when no verified primary email is found', async () => {
      mockRedis.get.mockResolvedValue(makeStoredState());
      mockFetchSequence(
        { json: { access_token: 'gh-token' } },
        { json: { id: 99, name: 'Dev' } },
        { json: [{ email: 'nope@example.com', primary: false, verified: true }] }
      );

      const req = mockReq({ query: { code: 'mycode', state: 'valid-state' } });

      await expect(provider.handleCallback(req)).rejects.toThrow(
        'OAuthError: No verified primary email found'
      );
    });

    it('returns profile, mode and userId on success', async () => {
      mockRedis.get.mockResolvedValue(
        makeStoredState({ userId: 'user-123', mode: 'link' })
      );
      mockFetchSequence(
        { json: { access_token: 'gh-token' } },
        { json: { id: 42, name: 'Dev User' } },
        {
          json: [
            { email: 'dev@example.com', primary: true, verified: true },
          ],
        }
      );

      const req = mockReq({ query: { code: 'mycode', state: 'valid-state' } });
      const result = await provider.handleCallback(req);

      expect(result.profile).toEqual({
        email: 'dev@example.com',
        name: 'Dev User',
        provider: 'github',
        providerId: '42',
        email_verified: true,
      });
      expect(result.mode).toBe('link');
      expect(result.userId).toBe('user-123');
    });

    it('deletes the state key from Redis after success', async () => {
      mockRedis.get.mockResolvedValue(makeStoredState());
      mockFetchSequence(
        { json: { access_token: 'gh-token' } },
        { json: { id: 42, name: 'Dev' } },
        { json: [{ email: 'dev@example.com', primary: true, verified: true }] }
      );

      const req = mockReq({ query: { code: 'mycode', state: 'valid-state' } });
      await provider.handleCallback(req);

      expect(mockRedis.del).toHaveBeenCalledWith('oauth:state:valid-state');
    });
  });
});
