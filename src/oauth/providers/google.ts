import { OAuth2Client } from "google-auth-library";
import { Request, Response } from "express";
import crypto from "crypto";
import { finalizeOAuthCallback } from "../callback";
import type { OAuthStateStore } from "../types";
import type { AuditEmitter } from "../../audit/types";
import {
  consumeOAuthState,
  OAUTH_STATE_BYTES,
  OAUTH_STATE_TTL_SECONDS,
} from "../state";
import {
  authenticatedUserId,
  OAUTH_HTTP_TIMEOUT_MS,
  readBoundedJsonResponse,
  readOAuthQueryValue,
  validateOAuthProviderConfig,
} from "../providerSecurity";
import {
  OAuthCallbackResult,
  OAuthProfile,
  GoogleOAuthConfig,
  IdentityEngine,
} from "../types";
import { containsControlCharacter } from "../../utility/safeString";
import { normalizeIdentityEmail } from "../identityValidation";

type GoogleTokenResponse = {
  access_token?: string;
  id_token?: string;
};

export function createGoogleProvider(
  config: GoogleOAuthConfig,
  stateStore: OAuthStateStore,
  identityEngine?: IdentityEngine,
  audit?: AuditEmitter,
) {
  const providerConfig = Object.freeze({ ...config });
  const { clientId } = providerConfig;
  validateOAuthProviderConfig(providerConfig);

  return {
    redirect: async (
      req: Request,
      res: Response,
      mode: "login" | "link" = "login",
    ): Promise<void> => {
      try {
        const state = crypto.randomBytes(OAUTH_STATE_BYTES).toString("hex");
        const userId = authenticatedUserId(req);
        if (mode === "link" && !userId) {
          res.status(401).json({ error: "Authentication required for linking" });
          return;
        }

        await stateStore.set(
          state,
          {
            userId: mode === "link" ? userId : null,
            mode,
          },
          OAUTH_STATE_TTL_SECONDS,
        );
        await audit?.emit({
          type: "oauth.state_created",
          severity: "info",
          outcome: "success",
          actor: userId
            ? { type: "user", id: userId }
            : { type: "unknown" },
          metadata: { provider: "google", mode },
        });

        res.redirect(googleAuthorizationUrl(providerConfig, state));
        return;
      } catch {
        res.status(500).json({ error: "OAuth redirect failed" });
        return;
      }
    },

    handleCallback: async (req: Request): Promise<OAuthCallbackResult> => {
      const code = readOAuthQueryValue(req, "code");
      const state = readOAuthQueryValue(req, "state");

      if (!state) {
        await audit?.emit({
          type: "oauth.state_rejected",
          severity: "warning",
          outcome: "denied",
          actor: { type: "unknown" },
          metadata: { provider: "google", reason: "missing" },
        });
        throw new Error("OAuthError:Missing state");
      }

      const stored = await consumeOAuthState(stateStore, state);

      if (!stored) {
        await audit?.emit({
          type: "oauth.state_rejected",
          severity: "warning",
          outcome: "denied",
          actor: { type: "unknown" },
          metadata: { provider: "google", reason: "invalid_or_expired" },
        });
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
        body: googleTokenRequestBody(providerConfig, code),
        signal: AbortSignal.timeout(OAUTH_HTTP_TIMEOUT_MS),
      });

      if (!tokenRes.ok) {
        throw new Error("OAuthError:Token exchange failed");
      }

      const tokenData = (await readBoundedJsonResponse(
        tokenRes,
      )) as GoogleTokenResponse;
      const profile = await verifiedGoogleProfile(tokenData, clientId);

      await audit?.emit({
        type: "oauth.state_consumed",
        severity: "info",
        outcome: "success",
        actor: userId
          ? { type: "user", id: userId }
          : { type: "unknown" },
        metadata: { provider: "google", mode },
      });
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
  if (
    typeof tokenData.access_token !== "string" ||
    tokenData.access_token.length === 0 ||
    tokenData.access_token.length > 4096 ||
    containsControlCharacter(tokenData.access_token)
  ) {
    throw new Error("OAuthError:No access token returned");
  }

  if (
    typeof tokenData.id_token !== "string" ||
    tokenData.id_token.length === 0 ||
    tokenData.id_token.length > 16 * 1024 ||
    containsControlCharacter(tokenData.id_token)
  ) {
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

  if (
    typeof payload.email !== "string" ||
    payload.email.length === 0 ||
    payload.email.length > 254 ||
    containsControlCharacter(payload.email)
  ) {
    throw new Error("OAuthError:Email not present in ID token");
  }

  if (payload.email_verified !== true) {
    throw new Error("OAuthError:Email not verified");
  }

  if (
    payload.iss !== "https://accounts.google.com" &&
    payload.iss !== "accounts.google.com"
  ) {
    throw new Error("OAuthError: Invalid issuer");
  }
  if (
    typeof payload.sub !== "string" ||
    payload.sub.length === 0 ||
    payload.sub.length > 512 ||
    containsControlCharacter(payload.sub)
  ) {
    throw new Error("OAuthError:Invalid subject in ID token");
  }

  return {
    email: normalizeIdentityEmail(payload.email),
    ...(typeof payload.name === "string"
      ? { name: payload.name.slice(0, 512) }
      : {}),
    provider: "google",
    providerId: payload.sub,
    email_verified: true,
  };
};
