import crypto from "crypto";
import { Request, Response } from "express";
import { finalizeOAuthCallback } from "../callback";
import type { OAuthStateStore } from "../types";
import {
  GitHubOAuthConfig,
  IdentityEngine,
  OAuthCallbackResult,
  OAuthProfile,
} from "../types";

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
  identityEngine?: IdentityEngine
) {
  return {
    redirect: async (
      req: Request,
      res: Response,
      mode: "login" | "link" = "login"
    ): Promise<void> => {
      if (res.headersSent) {
        return;
      }

      const state = crypto.randomBytes(32).toString("hex");
      const authUser = (req as any).user ?? null;

      await stateStore.set(
        state,
        {
          userId: authUser?.userId ?? null,
          mode,
        },
        300
      );

      res.redirect(githubAuthorizationUrl(config, state));
      return;
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
        throw new Error("OAuthError: Missing code");
      }

      const accessToken = await fetchGithubAccessToken(config, code);
      const profile = await verifiedGitHubProfile(accessToken);

      await stateStore.del(state);
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
  });
  const tokenData = (await tokenRes.json()) as GitHubAccessTokenResponse;

  if (!tokenData.access_token) {
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
    },
  });

  if (!userRes.ok) {
    throw new Error("OAuthError: Failed to fetch GitHub user");
  }

  const userData = (await userRes.json()) as GitHubUserResponse;
  const emailRes = await fetch("https://api.github.com/user/emails", {
    headers: {
      Authorization: `Bearer ${accessToken}`,
    },
  });

  const emails = (await emailRes.json()) as GitHubEmailResponse;
  const primaryEmail = emails.find((email) => email.primary && email.verified)
    ?.email;

  if (!primaryEmail) {
    throw new Error("OAuthError: No verified primary email found");
  }

  return {
    email: primaryEmail,
    name: userData.name,
    provider: "github",
    providerId: userData.id.toString(),
    email_verified: true,
  };
};
