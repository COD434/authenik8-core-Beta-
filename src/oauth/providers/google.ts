import { OAuthProfile, GoogleOAuthConfig } from "../types";
import { OAuth2Client } from "google-auth-library";
import {Request,Response} from "express";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import type { Redis as RedisClient } from "ioredis";
import type { IdentityEngine } from "../brain/types";

type GoogleTokenResponse = {
  access_token?: string;
  id_token?: string;
};

export function createGoogleProvider(config: GoogleOAuthConfig,redisClient:RedisClient, identityEngine: IdentityEngine) {
	const { clientId, clientSecret, redirectUri } = config;
	return {
		redirect:async (req:Request, res:Response): Promise<void> => {
			try{
				const state = crypto.randomBytes(32).toString("hex");
	

const mode = req.path.includes("link") ? "link" : "login";
const authUser = (req as any).user ?? null;

await redisClient.setex(`oauth:state:${state}`,300,JSON.stringify({
    userId: authUser?.userId ?? null,
    mode,
  })
);




      const url = new URL("https://accounts.google.com/o/oauth2/v2/auth");
     	url.searchParams.set("client_id", clientId);
     	url.searchParams.set("redirect_uri", redirectUri);
     	url.searchParams.set("response_type", "code");
	url.searchParams.set("scope", "openid email profile");
      	url.searchParams.set("access_type", "offline");
      	url.searchParams.set("prompt", "consent");
     	url.searchParams.set("state", state)

	res.redirect(url.toString());
	return;
			} catch {
				res.status(500).json({ error: "OAuth redirect failed" });
				return;
			}
		},
    handleCallback: async (req:Request): Promise<{profile: OAuthProfile;mode: "login" | "link";userId: string | null;}> => {
      const code = req.query.code as string;
      const client = new OAuth2Client(clientId);

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
        throw new Error("OauthError:Missing authorization code");
      }
      const params = new URLSearchParams();
      params.append("client_id", clientId);
      params.append("client_secret", clientSecret);
      params.append("code", code);
      params.append("grant_type", "authorization_code");
      params.append("redirect_uri", redirectUri);



      // Exchange code for tokens
      const tokenRes = await fetch("https://oauth2.googleapis.com/token", {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body:params
});

if(!tokenRes.ok){
const err = await tokenRes.text();
throw new Error(`OAuthError:Token exchange failed->${err}`)
}

      const tokenData = await tokenRes.json() as GoogleTokenResponse;
if(!tokenData.access_token){

	throw new Error("OAuthError:No access token returned")
}
if (!tokenData.id_token) {
  throw new Error("OAuthError:No id_token returned from Google");
}
const ticket = await client.verifyIdToken({
  idToken: tokenData.id_token,
  audience: clientId,
});

const payload = ticket.getPayload();

if(!payload){
throw new Error("OAuthError:Invalid ID token payload");
}
if(!payload.email){
throw new Error("OAuthError:Email not present in ID token");
}
if(!payload.email_verified){
throw new Error("OAuthError:Email not verified");
}

if (
  payload.iss !== "https://accounts.google.com" &&
  payload.iss !== "accounts.google.com"
) {
  throw new Error("OAuthError: Invalid issuer");
}
    
const profile: OAuthProfile = {
  email: payload.email,
  name: payload.name,
  provider: "google",
  providerId: payload.sub,
  email_verified:payload.email_verified ?? false
};

await redisClient.del(`oauth:state:${state}`);
return {
    profile,
    mode,
    userId,
  };
    
    }
  }
}
