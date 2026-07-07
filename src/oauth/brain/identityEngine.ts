import { IdentityEngine } from "../types";
import { IdentityContext, IdentityResult } from "../identity/types";
import { identityPolicy } from "./identityPolicy";
import { randomUUID } from "crypto";

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
  signAccessToken(payload: any): Promise<string> | string;
  generateRefreshToken(payload: any): Promise<string>;
};

export function createIdentityEngine(
  adapter: IdentityAdapter,
  tokenService: TokenService
): IdentityEngine {
  return {
    async resolveOAuth(args): Promise<IdentityResult> {
      const ctx: IdentityContext = {
        email: args.profile.email,
        provider: args.profile.provider,
        providerId: args.profile.providerId,
        mode: args.mode,
        userId: args.userId ?? undefined,
      };

      if (!ctx.email) {
        throw new Error("OAuth profile missing email");
      }

      if (!ctx.providerId) {
        throw new Error("Missing providerId");
      }

      const existingProvider = await adapter.findUserByProvider(
        ctx.provider,
        ctx.providerId
      );

      if (existingProvider) {
        return {
          type: "EXISTING_PROVIDER_LOGIN",
          user: existingProvider,
          ...(await issueTokensForUser(existingProvider, tokenService)),
        };
      }

      if (ctx.mode === "link") {
        if (!ctx.userId) {
          return {
            type: "INVALID_LINK_REQUEST",
            message: "Missing authenticated user for linking",
          };
        }

        await adapter.linkProvider(ctx.userId, ctx.provider, ctx.providerId);

        const user =
          (await adapter.findUserByEmail(ctx.email)) ??
          (await adapter.findUserByProvider(ctx.provider, ctx.providerId));

        if (!user) {
          throw new Error("LINK_PROVIDER: user resolution failed");
        }

        auditLogs.push({
          userId: user.id,
          action: "PROVIDER_LINKED",
          timestamp: Date.now(),
        });

        return {
          type: "LINK_PROVIDER",
          user,
          success: true,
        };
      }

      const existingUser = await adapter.findUserByEmail(ctx.email);

      if (existingUser) {
        if (!canAutoLink(args.profile.email_verified)) {
          return {
            type: "LINK_REQUIRED",
            message: "please link manually",
            email: ctx.email,
            provider: ctx.provider,
          };
        }

        return {
          type: "EXISTING_PROVIDER_LOGIN",
          user: existingUser,
          ...(await issueTokensForUser(existingUser, tokenService)),
        };
      }

      const user = await adapter.createUser({
        email: ctx.email,
        provider: ctx.provider,
        providerId: ctx.providerId,
      });

      auditLogs.push({
        userId: user.id,
        action: "USER_CREATED",
        timestamp: Date.now(),
      });

      return {
        type: "NEW_USER_CREATION",
        user,
        ...(await issueTokensForUser(user, tokenService)),
      };
    },
  };
}

const canAutoLink = (emailVerified: boolean | string): boolean => {
  const isVerified = emailVerified === true || emailVerified === "true";
  return (
    (isVerified && identityPolicy.autoLinkOnVerifiedEmailMatch) ||
    (!isVerified && identityPolicy.allowUnverifiedAutoLink)
  );
};

const issueTokensForUser = async (
  user: { id: string; email: string },
  tokenService: TokenService
) => {
  const payload = {
    userId: user.id,
    email: user.email,
    sessionId: randomUUID(),
  };

  return {
    accessToken: await tokenService.signAccessToken(payload),
    refreshToken: await tokenService.generateRefreshToken(payload),
  };
};
