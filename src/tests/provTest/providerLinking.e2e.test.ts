import type { Request, Response } from "express";
import { beforeEach, describe, expect, test, vi } from "vitest";
import { memoryAdapter } from "../../oauth/adapters/memoryAdapter";
import { createIdentityEngine } from "../../oauth/brain/identityEngine";
import { createRedisOAuthStateStore } from "../../oauth/core";
import { createGitHubProvider } from "../../oauth/providers/github";
import { createGoogleProvider } from "../../oauth/providers/google";

const { googlePayload } = vi.hoisted(() => ({
  googlePayload: {
    email: "shared@example.com",
    name: "Shared User",
    sub: "google-user-1",
    email_verified: true,
    iss: "https://accounts.google.com",
  },
}));

vi.mock("google-auth-library", () => ({
  OAuth2Client: vi.fn(function () {
    return {
      verifyIdToken: vi.fn().mockResolvedValue({
        getPayload: () => googlePayload,
      }),
    };
  }),
}));

class TestRedis {
  private readonly values = new Map<string, string>();

  async setex(key: string, _ttl: number, value: string) {
    this.values.set(key, value);
    return "OK";
  }

  async get(key: string) {
    return this.values.get(key) ?? null;
  }

  async del(key: string) {
    return this.values.delete(key) ? 1 : 0;
  }
}

const tokenService = {
  signAccessToken: ({ userId }: { userId: string }) => `access:${userId}`,
  generateRefreshToken: async ({ userId }: { userId: string }) =>
    `refresh:${userId}`,
};

const googleConfig = {
  clientId: "google-client",
  clientSecret: "google-secret",
  redirectUri: "https://app.example.com/oauth/google/callback",
};

const githubConfig = {
  clientId: "github-client",
  clientSecret: "github-secret",
  redirectUri: "https://app.example.com/oauth/github/callback",
};

const request = (
  path: string,
  overrides: Record<string, unknown> = {}
) =>
  ({
    path,
    query: {},
    user: null,
    ...overrides,
  }) as unknown as Request;

const response = () => {
  const res = {
    headersSent: false,
    redirect: vi.fn(),
    status: vi.fn().mockReturnThis(),
    json: vi.fn().mockReturnThis(),
  };

  return res as unknown as Response;
};

const stateFromResponse = (res: Response) => {
  const redirectUrl = vi.mocked(res.redirect).mock.calls[0]?.[0];
  expect(redirectUrl).toBeDefined();

  const state = new URL(String(redirectUrl)).searchParams.get("state");
  expect(state).toBeTruthy();
  return state as string;
};

const callbackRequest = (path: string, state: string) =>
  request(path, {
    query: {
      code: "authorization-code",
      state,
    },
  });

describe("OAuth provider linking end to end", () => {
  let redis: TestRedis;
  let identityEngine: ReturnType<typeof createIdentityEngine>;
  let google: ReturnType<typeof createGoogleProvider>;
  let github: ReturnType<typeof createGitHubProvider>;

  beforeEach(() => {
    memoryAdapter.reset();
    redis = new TestRedis();
    identityEngine = createIdentityEngine(memoryAdapter, tokenService);
    const stateStore = createRedisOAuthStateStore(redis);
    google = createGoogleProvider(googleConfig, stateStore, identityEngine);
    github = createGitHubProvider(githubConfig, stateStore, identityEngine);

    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: string | URL | Request) => {
        const url = input.toString();

        if (url === "https://oauth2.googleapis.com/token") {
          return {
            ok: true,
            json: async () => ({
              access_token: "google-access-token",
              id_token: "google-id-token",
            }),
          };
        }

        if (url === "https://github.com/login/oauth/access_token") {
          return {
            ok: true,
            json: async () => ({ access_token: "github-access-token" }),
          };
        }

        if (url === "https://api.github.com/user") {
          return {
            ok: true,
            json: async () => ({ id: 42, name: "Shared User" }),
          };
        }

        if (url === "https://api.github.com/user/emails") {
          return {
            ok: true,
            json: async () => [
              {
                email: "shared@example.com",
                primary: true,
                verified: true,
              },
            ],
          };
        }

        throw new Error(`Unexpected OAuth request: ${url}`);
      })
    );
  });

  test("Google user can link GitHub and later log in with the same user ID", async () => {
    const googleLoginResponse = response();
    await google.redirect(request("/oauth/google"), googleLoginResponse);
    const googleState = stateFromResponse(googleLoginResponse);
    const googleCallback = await google.handleCallback(
      callbackRequest("/oauth/google/callback", googleState)
    );
    const created = googleCallback.identity as any;

    expect(created.type).toBe("NEW_USER_CREATION");
    const userId = created.user.id;

    const githubLinkResponse = response();
    await github.redirect(
      request("/oauth/github/link", { user: { userId } }),
      githubLinkResponse,
      "link"
    );
    const githubLinkState = stateFromResponse(githubLinkResponse);
    const githubLinkCallback = await github.handleCallback(
      callbackRequest("/oauth/github/callback", githubLinkState)
    );
    const linked = githubLinkCallback.identity as any;

    expect(linked.type).toBe("LINK_PROVIDER");
    expect(linked.user.id).toBe(userId);
    expect(linked.user.providers).toEqual(
      expect.arrayContaining([
        { provider: "google", providerId: "google-user-1" },
        { provider: "github", providerId: "42" },
      ])
    );

    const githubLoginResponse = response();
    await github.redirect(request("/oauth/github"), githubLoginResponse);
    const githubLoginState = stateFromResponse(githubLoginResponse);
    const githubLoginCallback = await github.handleCallback(
      callbackRequest("/oauth/github/callback", githubLoginState)
    );
    const loggedIn = githubLoginCallback.identity as any;

    expect(loggedIn.type).toBe("EXISTING_PROVIDER_LOGIN");
    expect(loggedIn.user.id).toBe(userId);
    expect(loggedIn.accessToken).toBe(`access:${userId}`);
  });

  test("GitHub user can link Google and later log in with the same user ID", async () => {
    const githubLoginResponse = response();
    await github.redirect(request("/oauth/github"), githubLoginResponse);
    const githubState = stateFromResponse(githubLoginResponse);
    const githubCallback = await github.handleCallback(
      callbackRequest("/oauth/github/callback", githubState)
    );
    const created = githubCallback.identity as any;

    expect(created.type).toBe("NEW_USER_CREATION");
    const userId = created.user.id;

    const googleLinkResponse = response();
    await google.redirect(
      request("/oauth/google/link", { user: { userId } }),
      googleLinkResponse
    );
    const googleLinkState = stateFromResponse(googleLinkResponse);
    const googleLinkCallback = await google.handleCallback(
      callbackRequest("/oauth/google/callback", googleLinkState)
    );
    const linked = googleLinkCallback.identity as any;

    expect(linked.type).toBe("LINK_PROVIDER");
    expect(linked.user.id).toBe(userId);
    expect(linked.user.providers).toEqual(
      expect.arrayContaining([
        { provider: "github", providerId: "42" },
        { provider: "google", providerId: "google-user-1" },
      ])
    );

    const googleLoginResponse = response();
    await google.redirect(request("/oauth/google"), googleLoginResponse);
    const googleLoginState = stateFromResponse(googleLoginResponse);
    const googleLoginCallback = await google.handleCallback(
      callbackRequest("/oauth/google/callback", googleLoginState)
    );
    const loggedIn = googleLoginCallback.identity as any;

    expect(loggedIn.type).toBe("EXISTING_PROVIDER_LOGIN");
    expect(loggedIn.user.id).toBe(userId);
    expect(loggedIn.accessToken).toBe(`access:${userId}`);
  });
});
