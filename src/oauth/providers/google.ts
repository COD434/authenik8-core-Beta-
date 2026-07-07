import { OAuth2Client } from "google-auth-library";
import { Request, Response } from "express";
import crypto from "crypto";
import { finalizeOAuthCallback } from "../callback";
import type { OAuthStateStore } from "../identity/types";
import {
  OAuthCallbackResult,
  OAuthProfile,
  GoogleOAuthConfig,
  IdentityEngine,
} from "../types";

type GoogleTokenResponse = {
  access_token?: string;
  id_token?: string;
};

export function createGoogleProvider(
  config: GoogleOAuthConfig,
  stateStore: OAuthStateStore,
  identityEngine?: IdentityEngine
) {
  const { clientId, clientSecret, redirectUri } = config;

  return {
    redirect: async (req: Request, res: Response): Promise<void> => {
      try {
        const state = crypto.randomBytes(32).toString("hex");
        const mode = req.path.includes("link") ? "link" : "login";
        const authUser = (req as any).user ?? null;

        await stateStore.set(
          state,
          {
            userId: authUser?.userId ?? null,
            mode,
          },
          300
        );

        res.redirect(googleAuthorizationUrl(config, state));
        return;
      } catch {
        res.status(500).json({ error: "OAuth redirect failed" });
        return;
      }
    },

    handleCallback: async (req: Request): Promise<OAuthCallbackResult> => {
      const code = req.query.code as string;
      const state = req.query.state as string;

      if (!state) {
        throw new Error("OAuthError:Missing state");
      }

      const stored = await stateStore.get(state);

      if (!stored) {
        throw new Error("OAuthError:Invalid or expired state");
      }

      const { userId, mode } = stored;

      if (!code) {
        throw new Error("OauthError:Missing authorization code");
      }

      const tokenRes = await fetch("https://oauth2.googleapis.com/token", {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: googleTokenRequestBody(config, code),
      });

      if (!tokenRes.ok) {
        const err = await tokenRes.text();
        throw new Error(`OAuthError:Token exchange failed->${err}`);
      }

      const tokenData = (await tokenRes.json()) as GoogleTokenResponse;
      const profile = await verifiedGoogleProfile(tokenData, clientId);

      await stateStore.del(state);
      return finalizeOAuthCallback(profile, mode, userId, identityEngine);
    },
  };
}

const googleAuthorizationUrl = (
  config: GoogleOAuthConfig,
  state: string
): string => {
  const url = new URL("https://accounts.google.com/o/oauth2/v2/auth");
  url.searchParams.set("client_id", config.clientId);
  url.searchParams.set("redirect_uri", config.redirectUri);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("scope", "openid email profile");
  url.searchParams.set("access_type", "offline");
  url.searchParams.set("prompt", "consent");
  url.searchParams.set("state", state);
  return url.toString();
};

const googleTokenRequestBody = (
  config: GoogleOAuthConfig,
  code: string
): URLSearchParams => {
  const params = new URLSearchParams();
  params.append("client_id", config.clientId);
  params.append("client_secret", config.clientSecret);
  params.append("code", code);
  params.append("grant_type", "authorization_code");
  params.append("redirect_uri", config.redirectUri);
  return params;
};

const verifiedGoogleProfile = async (
  tokenData: GoogleTokenResponse,
  clientId: string
): Promise<OAuthProfile> => {
  if (!tokenData.access_token) {
    throw new Error("OAuthError:No access token returned");
  }

  if (!tokenData.id_token) {
    throw new Error("OAuthError:No id_token returned from Google");
  }

  const client = new OAuth2Client(clientId);
  const ticket = await client.verifyIdToken({
    idToken: tokenData.id_token,
    audience: clientId,
  });
  const payload = ticket.getPayload();

  if (!payload) {
    throw new Error("OAuthError:Invalid ID token payload");
  }

  if (!payload.email) {
    throw new Error("OAuthError:Email not present in ID token");
  }

  if (!payload.email_verified) {
    throw new Error("OAuthError:Email not verified");
  }

  if (
    payload.iss !== "https://accounts.google.com" &&
    payload.iss !== "accounts.google.com"
  ) {
    throw new Error("OAuthError: Invalid issuer");
  }

  return {
    email: payload.email,
    name: payload.name,
    provider: "google",
    providerId: payload.sub,
    email_verified: payload.email_verified ?? false,
  };
};
