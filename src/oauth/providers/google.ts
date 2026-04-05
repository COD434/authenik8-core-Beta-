import { OAuthProfile, GoogleOAuthConfig } from "./types";
import {Request,Response} from "express";
import jwt from "jsonwebtoken";


export function createGoogleProvider(config: GoogleOAuthConfig) {
  const { clientId, clientSecret, redirectUri } = config;

  return {

    redirect: (req:Request, res:Response) => {
	
      const url = new URL("https://accounts.google.com/o/oauth2/v2/auth");
     url.searchParams.set("client_id", clientId);
     url.searchParams.set("redirect_uri", redirectUri);
     url.searchParams.set("response_type", "code");
      url.searchParams.set("scope", "openid email profile");
      url.searchParams.set("access_type", "offline");
      url.searchParams.set("prompt", "consent");

      res.redirect(url.toString());
    },

    handleCallback: async (req:Request): Promise<{ profile: OAuthProfile }> => {
      const code = req.query.code as string;

      if (!code) {
        throw new Error("OauthError:Missing authorization code");
      }
      const params = new URLSearchParams();
      params.append("client_id", clientId);
      params.append("client_secret", clientSecret);
      params.append("code", code);
      params.append("grant_type", "authorization_code");
      params.append("redirect_uri", redirectUri);



      // 1. Exchange code for tokens
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

      const tokenData = await tokenRes.json();
if(!tokenData.access_token){
	console.log("TOKEN DATA:", tokenData);
	throw new Error("OAuthError:No access token returned")
}
const decoded = jwt.decode(tokenData.id_token) as any;
if(!decoded){
throw new Error("OAuthError:Failed to decode od_token")
}

console.log("DECODED ID TOKEN:", decoded);

if (!decoded.email) {
  throw new Error("OAuthError: Email not present in id_token");
}

      const accessToken = tokenData.access_token;
console.log("Token data:",tokenData);
      console.log("[OAuth] Fetching user profile...");
      //const profileRes = await fetch(
       // "https://www.googleapis.com/v1/userinfo",
     //   {
        //  headers: {
//Authorization: `Bearer ${accessToken}`,
          //},  }
     // );

      //const profileData = await profileRes.text();

    //  if(!tokenData.email){
      //throw new Error("OAuthError:Email not provided by provider")
    //  }

      const profile: OAuthProfile = {
        email: decoded.email,
        name: decoded.name,
        provider: "google",
        providerId: decoded.sub,
      };
      

      return { profile };
    },
  };
}
