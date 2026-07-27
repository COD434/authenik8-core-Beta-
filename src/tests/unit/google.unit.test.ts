import type { Request, Response } from "express";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { createGoogleProvider } from "../../oauth/providers/google";
import type { IdentityEngine, OAuthStateStore } from "../../oauth/types";

const { getPayload, verifyIdToken } = vi.hoisted(() => ({
  getPayload: vi.fn(),
  verifyIdToken: vi.fn(),
}));
vi.mock("google-auth-library", () => ({
  OAuth2Client: vi.fn(function () {
    return { verifyIdToken };
  }),
}));

const VALID_STATE = "a".repeat(64);
const config = {
  clientId: "google-client-id",
  clientSecret: "google-client-secret-32-bytes-minimum",
  redirectUri: "https://app.example.test/auth/google/callback",
};
const validPayload = {
  email: "dev@example.com",
  name: "Dev User",
  sub: "google-sub-999",
  email_verified: true,
  iss: "https://accounts.google.com",
};

const request = (overrides: Record<string, unknown> = {}) =>
  ({
    query: {},
    path: "/auth/google",
    socket: { remoteAddress: "192.0.2.1" },
    headers: {},
    ...overrides,
  }) as unknown as Request;

const response = () =>
  ({
    redirect: vi.fn(),
    status: vi.fn().mockReturnThis(),
    json: vi.fn().mockReturnThis(),
  }) as unknown as Response;

describe("createGoogleProvider", () => {
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
    verifyIdToken.mockResolvedValue({ getPayload });
    getPayload.mockReturnValue(validPayload);
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response(
          JSON.stringify({
          access_token: "google-access",
          id_token: "google-id",
          }),
          { status: 200 },
        ),
      ),
    );
  });

  it("creates 256-bit state and does not infer link mode from the path", async () => {
    const provider = createGoogleProvider(config, stateStore, identityEngine);
    const res = response();
    await provider.redirect(request({ path: "/auth/google/link" }), res);

    expect(stateStore.set).toHaveBeenCalledWith(
      expect.stringMatching(/^[a-f0-9]{64}$/),
      { mode: "login", userId: null },
      300,
    );
    const url = new URL(String(vi.mocked(res.redirect).mock.calls[0]![0]));
    expect(url.origin).toBe("https://accounts.google.com");
    expect(url.searchParams.get("state")).toMatch(/^[a-f0-9]{64}$/);
  });

  it("requires an authenticated user before creating link state", async () => {
    const provider = createGoogleProvider(config, stateStore, identityEngine);
    const res = response();
    await provider.redirect(request(), res, "link");

    expect(res.status).toHaveBeenCalledWith(401);
    expect(stateStore.set).not.toHaveBeenCalled();
    expect(res.redirect).not.toHaveBeenCalled();
  });

  it("binds explicit link state to the authenticated user", async () => {
    const provider = createGoogleProvider(config, stateStore, identityEngine);
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

  it("rejects malformed state without making an outbound request", async () => {
    const provider = createGoogleProvider(config, stateStore, identityEngine);
    await expect(
      provider.handleCallback(
        request({ query: { code: "code", state: "not-random" } }),
      ),
    ).rejects.toThrow(/invalid or expired state/i);
    expect(fetch).not.toHaveBeenCalled();
  });

  it("atomically consumes state before validating or exchanging the code", async () => {
    const provider = createGoogleProvider(config, stateStore, identityEngine);
    await expect(
      provider.handleCallback(request({ query: { state: VALID_STATE } })),
    ).rejects.toThrow(/missing authorization code/i);
    expect(stateStore.take).toHaveBeenCalledWith(VALID_STATE);
    expect(fetch).not.toHaveBeenCalled();
  });

  it("does not disclose the provider token error response", async () => {
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValue(
          new Response("provider secret details", { status: 400 }),
        ),
    );
    const provider = createGoogleProvider(config, stateStore, identityEngine);
    await expect(
      provider.handleCallback(
        request({ query: { code: "code", state: VALID_STATE } }),
      ),
    ).rejects.toThrow("OAuthError:Token exchange failed");
  });

  it("rejects unverified or malformed ID-token profiles", async () => {
    getPayload.mockReturnValue({ ...validPayload, email_verified: false });
    const provider = createGoogleProvider(config, stateStore, identityEngine);
    await expect(
      provider.handleCallback(
        request({ query: { code: "code", state: VALID_STATE } }),
      ),
    ).rejects.toThrow(/email not verified/i);
  });

  it("returns a verified profile and identity token pair", async () => {
    const provider = createGoogleProvider(config, stateStore, identityEngine);
    const result = await provider.handleCallback(
      request({ query: { code: "code", state: VALID_STATE } }),
    );

    expect(verifyIdToken).toHaveBeenCalledWith({
      idToken: "google-id",
      audience: config.clientId,
    });
    expect(vi.mocked(identityEngine.resolveOAuth)).toHaveBeenCalledWith({
      profile: {
        email: "dev@example.com",
        name: "Dev User",
        provider: "google",
        providerId: "google-sub-999",
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
});
