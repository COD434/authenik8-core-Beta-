import type { JSONWebKeySet, JWK, JWTPayload } from "jose" with {
    "resolution-mode": "import"
};
type JoseModule = typeof import("jose", { with: { "resolution-mode": "import" } });
export declare const loadJose: () => Promise<JoseModule>;
export declare const ACCESS_TOKEN_ALGORITHM: "ES256";
export declare const LEGACY_TOKEN_ALGORITHM: "HS256";
export declare const DEFAULT_TOKEN_ISSUER = "authenik8-core";
export declare const DEFAULT_TOKEN_AUDIENCE = "authenik8-api";
export type Authenik8TokenUse = "access" | "guest" | "refresh" | "agent" | "agent-delegation";
export interface Authenik8JwkConfig {
    keys: JWK[];
    activeKid: string;
    issuer: string;
    audience: string | string[];
}
export interface JwtKeyRingOptions {
    jwk?: Authenik8JwkConfig;
    legacySecret?: string;
    issuer?: string;
    audience?: string | string[];
}
export interface SignJwtOptions {
    expiresIn: string | number;
    tokenUse: Authenik8TokenUse;
}
export interface PublicJwksVerificationOptions {
    issuer: string;
    audience: string | string[];
}
export declare class JwtKeyRing {
    readonly issuer: string;
    readonly audience: string | string[];
    private readonly jwk?;
    private readonly legacySecret?;
    constructor(options: JwtKeyRingOptions);
    sign(payload: Record<string, unknown>, options: SignJwtOptions): Promise<string>;
    verify<T extends JWTPayload = JWTPayload>(token: string, tokenUse: Authenik8TokenUse): Promise<T>;
    getJwks(): JSONWebKeySet;
    private activePrivateJwk;
    private protectedHeader;
}
export declare const generateSigningJwk: (kid?: string) => Promise<JWK>;
export declare const verifyAccessTokenWithJwks: <T extends JWTPayload = JWTPayload>(token: string, jwks: JSONWebKeySet | URL, options: PublicJwksVerificationOptions) => Promise<T>;
export {};
//# sourceMappingURL=jwk.d.ts.map