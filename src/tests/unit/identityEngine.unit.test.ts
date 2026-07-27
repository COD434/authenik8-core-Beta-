import { beforeEach, describe, expect, it, vi } from "vitest";
import { createIdentityEngine } from "../../oauth/brain/identityEngine";
import {
  resolveIdentityPolicy,
  type IdentityPolicy,
} from "../../oauth/brain/identityPolicy";
import type {
  IdentityUser,
  OAuthIdentityAdapter,
  Provider,
} from "../../oauth/types";

const user: IdentityUser = {
  id: "user-123",
  email: "test@example.com",
  role: "ADMIN",
  providers: [{ provider: "google", providerId: "google-456" }],
};
const otherUser: IdentityUser = {
  id: "other-user",
  email: "other@example.com",
  providers: [{ provider: "github", providerId: "github-other" }],
};
const profile = {
  email: "test@example.com",
  provider: "google" as Provider,
  providerId: "google-456",
  email_verified: true,
};

describe("createIdentityEngine", () => {
  let adapter: OAuthIdentityAdapter;
  let issueTokens: (
    payload: {
      userId: string;
      email: string;
      sessionId: string;
      role?: string;
    },
  ) => Promise<{ accessToken: string; refreshToken: string }>;
  let policy: IdentityPolicy;

  beforeEach(() => {
    policy = {
      autoLinkOnVerifiedEmailMatch: false,
      allowUnverifiedAutoLink: false,
    };
    adapter = {
      findUserById: vi.fn().mockResolvedValue(null),
      findUserByEmail: vi.fn().mockResolvedValue(null),
      findUserByProvider: vi.fn().mockResolvedValue(null),
      createUser: vi.fn(),
      linkProvider: vi.fn().mockResolvedValue(undefined),
    };
    issueTokens = vi.fn(async () => ({
      accessToken: "mock-access-token",
      refreshToken: "mock-refresh-token",
    }));
  });

  const engine = () =>
    createIdentityEngine(adapter, { issueTokens }, undefined, policy);

  it("rejects missing or malformed identity claims", async () => {
    await expect(
      engine().resolveOAuth({
        profile: { ...profile, email: "" },
        mode: "login",
      }),
    ).rejects.toThrow(/invalid email/i);
    await expect(
      engine().resolveOAuth({
        profile: { ...profile, providerId: "" },
        mode: "login",
      }),
    ).rejects.toThrow(/providerId/i);
    await expect(
      engine().resolveOAuth({
        profile: { ...profile, email: "multiple@@example.com" },
        mode: "login",
      }),
    ).rejects.toThrow(/invalid email/i);
    await expect(
      engine().resolveOAuth({
        profile: { ...profile, provider: "GOOGLE" as Provider },
        mode: "login",
      }),
    ).rejects.toThrow(/provider/i);
    await expect(
      engine().resolveOAuth({
        profile: { ...profile, email: 42 as never },
        mode: "login",
      }),
    ).rejects.toThrow(/invalid email/i);
    await expect(
      engine().resolveOAuth({
        profile,
        mode: "unexpected" as never,
      }),
    ).rejects.toThrow(/mode/i);
    expect(adapter.findUserByProvider).not.toHaveBeenCalled();
  });

  it("issues one atomic token pair for an existing provider login", async () => {
    vi.mocked(adapter.findUserByProvider).mockResolvedValue(user);

    const result = await engine().resolveOAuth({
      profile,
      mode: "login",
    });

    expect(result).toMatchObject({
      type: "EXISTING_PROVIDER_LOGIN",
      user,
      accessToken: "mock-access-token",
      refreshToken: "mock-refresh-token",
    });
    expect(vi.mocked(issueTokens)).toHaveBeenCalledOnce();
    expect(vi.mocked(issueTokens)).toHaveBeenCalledWith({
      userId: user.id,
      email: user.email,
      role: "admin",
      sessionId: expect.any(String),
    });
  });

  it("never turns a link callback into a login for the provider owner", async () => {
    vi.mocked(adapter.findUserByProvider).mockResolvedValue({
      ...otherUser,
      providers: [
        { provider: profile.provider, providerId: profile.providerId },
      ],
    });
    vi.mocked(adapter.findUserById).mockResolvedValue(user);

    const result = await engine().resolveOAuth({
      profile,
      mode: "link",
      userId: user.id,
    });

    expect(result).toMatchObject({
      type: "INVALID_LINK_REQUEST",
      message: "Provider cannot be linked",
    });
    expect(adapter.linkProvider).not.toHaveBeenCalled();
    expect(vi.mocked(issueTokens)).not.toHaveBeenCalled();
  });

  it("rejects an adapter index that returns a user without the exact provider", async () => {
    vi.mocked(adapter.findUserByProvider).mockResolvedValue(otherUser);

    await expect(
      engine().resolveOAuth({ profile, mode: "login" }),
    ).rejects.toThrow(/provider mismatch/i);
    expect(vi.mocked(issueTokens)).not.toHaveBeenCalled();
  });

  it("links only to the authenticated state user and verifies the link", async () => {
    const linked = {
      ...user,
      email: "account-email@example.com",
      providers: [...user.providers, { provider: "github", providerId: "gh-1" }],
    };
    vi.mocked(adapter.findUserById)
      .mockResolvedValueOnce(user)
      .mockResolvedValueOnce(linked);

    const result = await engine().resolveOAuth({
      profile: {
        ...profile,
        email: "provider-email@example.com",
        provider: "github",
        providerId: "gh-1",
      },
      mode: "link",
      userId: user.id,
    });

    expect(adapter.findUserByEmail).not.toHaveBeenCalled();
    expect(adapter.linkProvider).toHaveBeenCalledWith(
      user.id,
      "github",
      "gh-1",
    );
    expect(result).toMatchObject({ type: "LINK_PROVIDER", user: linked });
    expect(vi.mocked(issueTokens)).not.toHaveBeenCalled();
  });

  it("requires an authenticated target for link mode", async () => {
    const result = await engine().resolveOAuth({
      profile,
      mode: "link",
    });
    expect(result.type).toBe("INVALID_LINK_REQUEST");
    expect(adapter.linkProvider).not.toHaveBeenCalled();
  });

  it("rejects an adapter ID lookup that returns a different link target", async () => {
    vi.mocked(adapter.findUserById).mockResolvedValue(otherUser);

    const result = await engine().resolveOAuth({
      profile,
      mode: "link",
      userId: user.id,
    });

    expect(result.type).toBe("INVALID_LINK_REQUEST");
    expect(adapter.linkProvider).not.toHaveBeenCalled();
    expect(vi.mocked(issueTokens)).not.toHaveBeenCalled();
  });

  it("does not issue tokens for an email match when auto-link is disabled", async () => {
    vi.mocked(adapter.findUserByEmail).mockResolvedValue(user);

    const result = await engine().resolveOAuth({ profile, mode: "login" });

    expect(result.type).toBe("LINK_REQUIRED");
    expect(adapter.linkProvider).not.toHaveBeenCalled();
    expect(vi.mocked(issueTokens)).not.toHaveBeenCalled();
  });

  it("persists and verifies an explicitly permitted verified-email link before tokens", async () => {
    policy = {
      ...policy,
      autoLinkOnVerifiedEmailMatch: true,
    };
    const linked = {
      ...user,
      providers: [...user.providers, { provider: "github", providerId: "gh-2" }],
    };
    vi.mocked(adapter.findUserByEmail).mockResolvedValue(user);
    vi.mocked(adapter.findUserByProvider)
      .mockResolvedValueOnce(null)
      .mockResolvedValueOnce(linked);

    const result = await engine().resolveOAuth({
      profile: {
        ...profile,
        provider: "github",
        providerId: "gh-2",
      },
      mode: "login",
    });

    expect(adapter.linkProvider).toHaveBeenCalledBefore(vi.mocked(issueTokens));
    expect(result.type).toBe("EXISTING_PROVIDER_LOGIN");
  });

  it("does not treat string-like verification values as verified email", async () => {
    policy = {
      ...policy,
      autoLinkOnVerifiedEmailMatch: true,
    };
    vi.mocked(adapter.findUserByEmail).mockResolvedValue(user);

    await expect(
      engine().resolveOAuth({
        profile: { ...profile, email_verified: "true" as never },
        mode: "login",
      }),
    ).rejects.toThrow(/verification claim/i);
    expect(adapter.linkProvider).not.toHaveBeenCalled();
    expect(vi.mocked(issueTokens)).not.toHaveBeenCalled();
  });

  it("issues tokens for a newly and atomically created user", async () => {
    vi.mocked(adapter.createUser).mockResolvedValue({
      status: "created",
      user,
    });

    const result = await engine().resolveOAuth({ profile, mode: "login" });

    expect(result.type).toBe("NEW_USER_CREATION");
    expect(vi.mocked(issueTokens)).toHaveBeenCalledOnce();
  });

  it("fails closed when a concurrent create reports an email collision", async () => {
    vi.mocked(adapter.createUser).mockResolvedValue({
      status: "existing-email",
      user,
    });

    const result = await engine().resolveOAuth({ profile, mode: "login" });

    expect(result.type).toBe("LINK_REQUIRED");
    expect(vi.mocked(issueTokens)).not.toHaveBeenCalled();
  });

  it("accepts a concurrent create only when the exact provider won", async () => {
    vi.mocked(adapter.createUser).mockResolvedValue({
      status: "existing-provider",
      user,
    });

    const result = await engine().resolveOAuth({ profile, mode: "login" });

    expect(result.type).toBe("EXISTING_PROVIDER_LOGIN");
    expect(vi.mocked(issueTokens)).toHaveBeenCalledOnce();
  });

  it("requires policy flags to be actual booleans", () => {
    expect(() =>
      resolveIdentityPolicy({
        autoLinkOnVerifiedEmailMatch: "true" as never,
      }),
    ).toThrow(/boolean/i);
  });
});
