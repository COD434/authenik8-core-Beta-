import type { Request, Response } from "express";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { createGitHubProvider } from "../../oauth/providers/github";
import type { IdentityEngine, OAuthStateStore } from "../../oauth/types";

const VALID_STATE = "b".repeat(64);
const config = {
  clientId: "github-client-id",
  clientSecret: "github-client-secret-32-bytes-minimum",
  redirectUri: "https://app.example.test/auth/github/callback",
};
const request = (overrides: Record<string, unknown> = {}) =>
  ({
    query: {},
    headers: {},
    socket: { remoteAddress: "192.0.2.1" },
    ...overrides,
  }) as unknown as Request;
const response = () =>
  ({
    headersSent: false,
    redirect: vi.fn(),
    status: vi.fn().mockReturnThis(),
    json: vi.fn().mockReturnThis(),
  }) as unknown as Response;

describe("createGitHubProvider", () => {
  let stateStore: OAuthStateStore;
  let identityEngine: IdentityEngine;

  beforeEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
    stateStore = {
      set: vi.fn().mockResolvedValue(undefined),
      take: vi.fn().mockResolvedValue({ mode: "login", userId: null }),
    };
    identityEngine = {
      resolveOAuth: vi.fn(async () => ({
        type: "EXISTING_PROVIDER_LOGIN" as const,
        user: {
          id: "user-1",
          email: "dev@example.com",
          providers: [],
        },
        accessToken: "access",
        refreshToken: "refresh",
      })),
    };
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValueOnce(
          new Response(JSON.stringify({ access_token: "github-access" })),
        )
        .mockResolvedValueOnce(
          new Response(JSON.stringify({ id: 42, name: "Dev User" })),
        )
        .mockResolvedValueOnce(
          new Response(
            JSON.stringify([
            {
              email: "dev@example.com",
              primary: true,
              verified: true,
            },
            ]),
          ),
        ),
    );
  });

  it("creates 256-bit login state and the expected authorization URL", async () => {
    const provider = createGitHubProvider(config, stateStore, identityEngine);
    const res = response();
    await provider.redirect(request(), res);

    expect(stateStore.set).toHaveBeenCalledWith(
      expect.stringMatching(/^[a-f0-9]{64}$/),
      { mode: "login", userId: null },
      300,
    );
    const url = new URL(String(vi.mocked(res.redirect).mock.calls[0]![0]));
    expect(url.origin).toBe("https://github.com");
    expect(url.searchParams.get("scope")).toBe("read:user user:email");
  });

  it("requires authentication for link state", async () => {
    const provider = createGitHubProvider(config, stateStore, identityEngine);
    const res = response();
    await provider.redirect(request(), res, "link");
    expect(res.status).toHaveBeenCalledWith(401);
    expect(stateStore.set).not.toHaveBeenCalled();
  });

  it("binds link state to the authenticated user", async () => {
    const provider = createGitHubProvider(config, stateStore, identityEngine);
    await provider.redirect(
      request({ user: { userId: "user-1" } }),
      response(),
      "link",
    );
    expect(stateStore.set).toHaveBeenCalledWith(
      expect.any(String),
      { mode: "link", userId: "user-1" },
      300,
    );
  });

  it("rejects malformed state before outbound requests", async () => {
    const provider = createGitHubProvider(config, stateStore, identityEngine);
    await expect(
      provider.handleCallback(
        request({ query: { code: "code", state: "forged" } }),
      ),
    ).rejects.toThrow(/invalid or expired state/i);
    expect(fetch).not.toHaveBeenCalled();
  });

  it("atomically consumes state even when the code is missing", async () => {
    const provider = createGitHubProvider(config, stateStore, identityEngine);
    await expect(
      provider.handleCallback(request({ query: { state: VALID_STATE } })),
    ).rejects.toThrow(/missing code/i);
    expect(stateStore.take).toHaveBeenCalledWith(VALID_STATE);
    expect(fetch).not.toHaveBeenCalled();
  });

  it("checks HTTP status for token, user, and email responses", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(new Response("{}", { status: 400 })),
    );
    const provider = createGitHubProvider(config, stateStore, identityEngine);
    await expect(
      provider.handleCallback(
        request({ query: { code: "code", state: VALID_STATE } }),
      ),
    ).rejects.toThrow(/token exchange failed/i);
  });

  it("requires a verified primary email", async () => {
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValueOnce(
          new Response(JSON.stringify({ access_token: "github-access" })),
        )
        .mockResolvedValueOnce(new Response(JSON.stringify({ id: 42 })))
        .mockResolvedValueOnce(
          new Response(
            JSON.stringify([
              {
                email: "dev@example.com",
                primary: true,
                verified: false,
              },
            ]),
          ),
        ),
    );
    const provider = createGitHubProvider(config, stateStore, identityEngine);
    await expect(
      provider.handleCallback(
        request({ query: { code: "code", state: VALID_STATE } }),
      ),
    ).rejects.toThrow(/verified primary email/i);
  });

  it("returns the verified profile and identity token pair", async () => {
    const provider = createGitHubProvider(config, stateStore, identityEngine);
    const result = await provider.handleCallback(
      request({ query: { code: "code", state: VALID_STATE } }),
    );

    expect(vi.mocked(identityEngine.resolveOAuth)).toHaveBeenCalledWith({
      profile: {
        email: "dev@example.com",
        name: "Dev User",
        provider: "github",
        providerId: "42",
        email_verified: true,
      },
      mode: "login",
      userId: null,
    });
    expect(result).toMatchObject({
      accessToken: "access",
      refreshToken: "refresh",
    });
  });

  it("rejects the misleading unsupported enterprise flag", () => {
    expect(() =>
      createGitHubProvider(
        { ...config, enterprise: true },
        stateStore,
        identityEngine,
      ),
    ).toThrow(/enterprise/i);
  });
});
