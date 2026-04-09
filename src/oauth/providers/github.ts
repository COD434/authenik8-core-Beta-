import crypto from "crypto";
import { Request, Response } from "express";
import { OAuthProfile } from "../types";
import type { Redis as RedisClient } from "ioredis";
import { GitHubOAuthConfig, GoogleOAuthConfig } from "../types";
import { linkProvider } from "../userStore";
import type { IdentityEngine } from "../brain/types";

export function createGitHubProvider(config:GitHubOAuthConfig,
				     redisClient:RedisClient,
				    identityEngine:IdentityEngine) {
  const { clientId, clientSecret, redirectUri } = config;

  return {
    redirect: async (req: Request, res: Response,mode: "login" | "link" = "login"):Promise<void> => {



  if (res.headersSent) {
    console.log("🚨 HEADERS ALREADY SENT — SKIPPING");
    return;
  }


const state= crypto.randomBytes(32).toString("hex");
const authUser = (req as any).user ?? null;




await redisClient.setex(
  `oauth:state:${state}`,
  300,
  JSON.stringify({
    userId: authUser?.userId ?? null,
    mode,
  })
);



      const url = new URL("https://github.com/login/oauth/authorize");

      url.searchParams.set("client_id", clientId);
      url.searchParams.set("redirect_uri", redirectUri);
      url.searchParams.set("scope", "read:user user:email");
      url.searchParams.set("state",state);
      
      console.log("REDIRECT STATE:", {
    userId: authUser?.userId,
    mode,
  });

      res.redirect(url.toString());
      return
      
    },
    

    handleCallback:
 async (req: Request): Promise<{
	profile: OAuthProfile;
	 mode: "login" | "link";
        userId: string | null;
    }> => {
      const code = req.query.code as string;
    const state = req.query.state as string;

    if (!state) {
      throw new Error("OAuthError:Missing state");
    }

    const stored = await redisClient.get(`oauth:state:${state}`);

    if (!stored) {
      throw new Error("OAuthError:Invalid or expired state");
    }

 

    const { userId, mode } = JSON.parse(stored);

      if (!code) {
        throw new Error("OAuthError: Missing code");
      }

      const params = new URLSearchParams();
      params.append("client_id", clientId);
      params.append("client_secret", clientSecret);
      params.append("code", code);

      const tokenRes = await fetch("https://github.com/login/oauth/access_token", {
        method: "POST",
        headers: {
          Accept: "application/json",
        },
        body: params,
      });

      const tokenData = await tokenRes.json();

      if (!tokenData.access_token) {
        throw new Error("OAuthError: No access token from Github");
      }

      const accessToken = tokenData.access_token;

      
      const userRes = await fetch("https://api.github.com/user", {
        headers: {
          Authorization: `Bearer  ${accessToken}`,
        },
      });
      if (!userRes.ok) {
  throw new Error("OAuthError: Failed to fetch GitHub user");
}

      const userData = await userRes.json();

      
      const emailRes = await fetch("https://api.github.com/user/emails", {
        headers: {
          Authorization: `Bearer ${accessToken}`,
        },
      });

      const emails = await emailRes.json();

      const primaryEmail = emails.find((e: any) => e.primary)?.email;

      if (!primaryEmail) {
        throw new Error("OAuthError: No primary email  found");
      }

      const profile: OAuthProfile = {
        email: primaryEmail,
        name: userData.name,
        provider: "github",
        providerId: userData.id.toString(),
      };


await redisClient.del(`oauth:state:${state}`);

return {
profile,
mode,
userId
};

    },
  };
}
  
