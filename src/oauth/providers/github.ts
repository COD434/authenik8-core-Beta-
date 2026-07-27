import crypto from "crypto";
import { Request, Response } from "express";
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
  GitHubOAuthConfig,
  IdentityEngine,
  OAuthCallbackResult,
  OAuthProfile,
} from "../types";
import { containsControlCharacter } from "../../utility/safeString";
import { normalizeIdentityEmail } from "../identityValidation";

type GitHubAccessTokenResponse = {
  access_token?: string;
};

type GitHubEmailResponse = Array<{
  email: string;
  primary?: boolean;
  verified?: boolean;
}>;

type GitHubUserResponse = {
  id: number;
  name?: string;
};

export function createGitHubProvider(
  config: GitHubOAuthConfig,
  stateStore: OAuthStateStore,
  identityEngine?: IdentityEngine,
  audit?: AuditEmitter,
) {
  const providerConfig = Object.freeze({ ...config });
  validateOAuthProviderConfig(providerConfig);
  if (providerConfig.enterprise) {
    throw new Error(
      "GitHub Enterprise OAuth requires explicit trusted endpoint configuration and is not supported by this adapter",
    );
  }

  return {
    redirect: async (
      req: Request,
      res: Response,
      mode: "login" | "link" = "login"
    ): Promise<void> => {
      if (res.headersSent) {
        return;
      }

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
        metadata: { provider: "github", mode },
      });

      res.redirect(githubAuthorizationUrl(providerConfig, state));
      return;
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
          metadata: { provider: "github", reason: "missing" },
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
          metadata: { provider: "github", reason: "invalid_or_expired" },
        });
        throw new Error("OAuthError:Invalid or expired state");
      }

      const { userId, mode } = stored;

      if (!code) {
        throw new Error("OAuthError: Missing code");
      }

      const accessToken = await fetchGithubAccessToken(providerConfig, code);
      const profile = await verifiedGitHubProfile(accessToken);

      await audit?.emit({
        type: "oauth.state_consumed",
        severity: "info",
        outcome: "success",
        actor: userId
          ? { type: "user", id: userId }
          : { type: "unknown" },
        metadata: { provider: "github", mode },
      });
      return finalizeOAuthCallback(profile, mode, userId, identityEngine);
    },
  };
}

const githubAuthorizationUrl = (
  config: GitHubOAuthConfig,
  state: string
): string => {
  const url = new URL("https://github.com/login/oauth/authorize");
  url.searchParams.set("client_id", config.clientId);
  url.searchParams.set("redirect_uri", config.redirectUri);
  url.searchParams.set("scope", "read:user user:email");
  url.searchParams.set("state", state);
  return url.toString();
};

const fetchGithubAccessToken = async (
  config: GitHubOAuthConfig,
  code: string
): Promise<string> => {
  const params = new URLSearchParams();
  params.append("client_id", config.clientId);
  params.append("client_secret", config.clientSecret);
  params.append("code", code);

  const tokenRes = await fetch("https://github.com/login/oauth/access_token", {
    method: "POST",
    headers: {
      Accept: "application/json",
    },
    body: params,
    signal: AbortSignal.timeout(OAUTH_HTTP_TIMEOUT_MS),
  });
  if (!tokenRes.ok) {
    throw new Error("OAuthError: GitHub token exchange failed");
  }
  const tokenData = (await readBoundedJsonResponse(
    tokenRes,
  )) as GitHubAccessTokenResponse;

  if (
    typeof tokenData.access_token !== "string" ||
    tokenData.access_token.length === 0 ||
    tokenData.access_token.length > 4096 ||
    containsControlCharacter(tokenData.access_token)
  ) {
    throw new Error("OAuthError: No access token from Github");
  }

  return tokenData.access_token;
};

const verifiedGitHubProfile = async (
  accessToken: string
): Promise<OAuthProfile> => {
  const userRes = await fetch("https://api.github.com/user", {
    headers: {
      Authorization: `Bearer ${accessToken}`,
      Accept: "application/vnd.github+json",
    },
    signal: AbortSignal.timeout(OAUTH_HTTP_TIMEOUT_MS),
  });

  if (!userRes.ok) {
    throw new Error("OAuthError: Failed to fetch GitHub user");
  }

  const userValue = await readBoundedJsonResponse(userRes);
  if (
    !userValue ||
    typeof userValue !== "object" ||
    !Number.isSafeInteger((userValue as Partial<GitHubUserResponse>).id) ||
    (userValue as Partial<GitHubUserResponse>).id! <= 0
  ) {
    throw new Error("OAuthError: Invalid GitHub user identifier");
  }
  const userData = userValue as GitHubUserResponse;
  const emailRes = await fetch("https://api.github.com/user/emails", {
    headers: {
      Authorization: `Bearer ${accessToken}`,
      Accept: "application/vnd.github+json",
    },
    signal: AbortSignal.timeout(OAUTH_HTTP_TIMEOUT_MS),
  });
  if (!emailRes.ok) {
    throw new Error("OAuthError: Failed to fetch GitHub emails");
  }

  const emailsValue = await readBoundedJsonResponse(emailRes);
  if (!Array.isArray(emailsValue) || emailsValue.length > 100) {
    throw new Error("OAuthError: Invalid GitHub email response");
  }
  const emails = emailsValue as GitHubEmailResponse;
  const primaryEmail = emails.find(
    (email) =>
      !!email &&
      typeof email === "object" &&
      email.primary === true &&
      email.verified === true &&
      typeof email.email === "string",
  )?.email;

  if (
    typeof primaryEmail !== "string" ||
    primaryEmail.length === 0 ||
    primaryEmail.length > 254 ||
    containsControlCharacter(primaryEmail)
  ) {
    throw new Error("OAuthError: No verified primary email found");
  }

  return {
    email: normalizeIdentityEmail(primaryEmail),
    ...(typeof userData.name === "string"
      ? { name: userData.name.slice(0, 512) }
      : {}),
    provider: "github",
    providerId: userData.id.toString(),
    email_verified: true,
  };
};
