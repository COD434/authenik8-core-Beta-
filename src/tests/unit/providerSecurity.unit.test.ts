import type { Request } from "express";
import { describe, expect, it } from "vitest";
import {
  authenticatedUserId,
  MAX_OAUTH_JSON_RESPONSE_BYTES,
  readBoundedJsonResponse,
  validateOAuthProviderConfig,
} from "../../oauth/providerSecurity";

describe("OAuth provider security boundaries", () => {
  it("allows HTTPS and loopback HTTP redirects but rejects remote HTTP", () => {
    const base = {
      clientId: "client",
      clientSecret: "client-secret-at-least-16-bytes",
    };

    expect(() =>
      validateOAuthProviderConfig({
        ...base,
        redirectUri: "https://app.example.test/oauth/callback",
      }),
    ).not.toThrow();
    expect(() =>
      validateOAuthProviderConfig({
        ...base,
        redirectUri: "http://127.0.0.1:3000/oauth/callback",
      }),
    ).not.toThrow();
    expect(() =>
      validateOAuthProviderConfig({
        ...base,
        redirectUri: "http://app.example.test/oauth/callback",
      }),
    ).toThrow(/HTTPS/i);
  });

  it("bounds provider JSON while reading the response stream", async () => {
    const oversized = new Response(
      JSON.stringify({ value: "x".repeat(MAX_OAUTH_JSON_RESPONSE_BYTES) }),
      { headers: { "content-type": "application/json" } },
    );
    await expect(readBoundedJsonResponse(oversized)).rejects.toThrow(
      /size limit/i,
    );

    const valid = new Response(JSON.stringify({ access_token: "token" }));
    await expect(readBoundedJsonResponse(valid)).resolves.toEqual({
      access_token: "token",
    });
  });

  it("rejects control characters in authenticated link identities", () => {
    const request = {
      user: { userId: "user\nforged" },
    } as unknown as Request;
    expect(authenticatedUserId(request)).toBeNull();
  });
});
