import type { Request } from "express";
export declare const OAUTH_HTTP_TIMEOUT_MS = 10000;
export declare const MAX_OAUTH_CODE_LENGTH = 4096;
export declare const MAX_OAUTH_JSON_RESPONSE_BYTES: number;
export declare const readBoundedJsonResponse: (response: Response, maximumBytes?: number) => Promise<unknown>;
export declare const validateOAuthProviderConfig: (config: {
    clientId: string;
    clientSecret: string;
    redirectUri: string;
}) => void;
export declare const readOAuthQueryValue: (request: Request, name: "code" | "state") => string | null;
export declare const authenticatedUserId: (request: Request) => string | null;
//# sourceMappingURL=providerSecurity.d.ts.map