
import dotenv from "dotenv";
import express from "express";
import { createAuthenik8 } from "../createAuthenik8";


dotenv.config()

const app = express();

async function start() {
  const auth = await createAuthenik8({
    jwtSecret: "test",
    refreshSecret: "test",
    oauth: {
      google: {
        clientId: process.env.GOOGLE_CLIENT_ID!,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
        redirectUri: "http://localhost:4000/callback",
      },
    },
  });

  app.get("/auth/google", auth.oauth!.google!.redirect);

  app.get("/callback", async (req, res) => {
    try {
      const { profile } = await auth.oauth!.google!.handleCallback(req);
      res.json(profile);
    } catch (err) {
      let message = "unknown error"

      if(err instanceof Error){
      message = err.message;
      }
      console.error("OAuth error:",message);
      res.status(500).json({error:message
      });
    }
  });

  app.listen(4000, () => {
    console.log("OAuth test server running on http://localhost:4000");
  });
}

start();
