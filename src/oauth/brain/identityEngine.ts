import { OAuthProfile } from "../types";
import { memoryAdapter } from "../adapters/memoryAdapter";
import { IdentityEngine } from "./types";
import { IdentityContext, IdentityResult } from "../identity/types";

const auditLogs: any[] = [];
type IdentityAdapter = {
  findUserByEmail(email: string): Promise<any>;
  findUserByProvider(provider: string, providerId: string): Promise<any>;
  createUser(data: {
    email: string;
    provider: string;
    providerId: string;
  }): Promise<any>;
  linkProvider(
    userId: string,
    provider: string,
    providerId: string
  ): Promise<void>;
};
type TokenService = {
  signAccessToken(payload: any): string;
  generateRefreshToken(payload: any): Promise<string>;
};

export function createIdentityEngine(
	adapter:IdentityAdapter,
  tokenService:TokenService
): IdentityEngine {
  return {
    async resolveOAuth(args):Promise<IdentityResult>{
	    const ctx:IdentityContext = {
	    email: args.profile.email, 
	    provider:args.profile.provider,
	    providerId:args.profile.providerId,
	    mode:args.mode,
	    userId: args.userId ?? undefined,
	    }
	    
if (!ctx.email) {
  throw new Error("OAuth profile missing email");
}
      // 1. Existing provider
      const existingProvider = await adapter.findUserByProvider(
        ctx.provider,
        ctx.providerId
      );

      if (existingProvider) {
const payload ={userId:existingProvider.id}
        return {
	type:"EXISTING_PROVIDER_LOGIN",
          user: existingProvider,
accessToken:tokenService.signAccessToken(payload),
refreshToken: await tokenService.generateRefreshToken(payload),
        };
      }

      // 2. LINK FLOW
      if (ctx.mode === "link") {

        if (!ctx.userId) {
		return{
		
		type:"INVALID_LINK_REQUEST",
		message:"Missing authenticated user for linking",
		}
        }
	if (existingProvider && existingProvider.id !== ctx.userId) {
    throw new Error("Provider already linked to another user");
  }

        await adapter.linkProvider(
		ctx.userId, 
		ctx.provider,
		ctx.providerId
	);
	let user = await adapter.findUserByEmail(ctx.email);

	if (!user) {
  user = await adapter.findUserByProvider(ctx.provider, ctx.providerId);
}
if (!user) {
  throw new Error("LINK_PROVIDER: user resolution failed");
}
	auditLogs.push({
  userId: user.id,
  action: "PROVIDER_LINKED",
  timestamp: Date.now(),
});
        return{
	type: "LINK_PROVIDER",
	user,
	success: true,
	}
      }

      // 3. Check existing by email OR provider (idempotency safety)

let existingUser = await adapter.findUserByEmail(ctx.email);


if (existingUser) {
  const payload = { userId: existingUser.id };

  return {
    type: "EXISTING_PROVIDER_LOGIN",
    user: existingUser,
    accessToken: tokenService.signAccessToken(payload),
    refreshToken: await tokenService.generateRefreshToken(payload),
  };

}


      // 4. Create new user
       const user = await adapter.createUser({
          email:ctx.email,
          provider:ctx.provider,
          providerId:ctx.providerId,
});
    if (!ctx.providerId) {
  throw new Error("Missing providerId");
}

const payload = { userId: user.id };
auditLogs.push({
  userId: user.id,
  action: "USER_CREATED",
  timestamp: Date.now(),
});

      return {
	      type:"NEW_USER_CREATION",
        user,
        accessToken:tokenService.signAccessToken(payload),
	refreshToken:await tokenService.generateRefreshToken(payload)
      };
    },
  };
}
