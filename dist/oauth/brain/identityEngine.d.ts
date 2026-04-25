import { IdentityEngine } from "./types";
type IdentityAdapter = {
    findUserByEmail(email: string): Promise<any>;
    findUserByProvider(provider: string, providerId: string): Promise<any>;
    createUser(data: {
        email: string;
        provider: string;
        providerId: string;
    }): Promise<any>;
    linkProvider(userId: string, provider: string, providerId: string): Promise<void>;
};
type TokenService = {
    signAccessToken(payload: any): string;
    generateRefreshToken(payload: any): Promise<string>;
};
export declare function createIdentityEngine(adapter: IdentityAdapter, tokenService: TokenService): IdentityEngine;
export {};
//# sourceMappingURL=identityEngine.d.ts.map