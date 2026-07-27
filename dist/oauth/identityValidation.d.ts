import type { IdentityUser } from "./types";
export declare const MAX_IDENTITY_EMAIL_LENGTH = 254;
export declare const MAX_IDENTITY_USER_ID_LENGTH = 256;
export declare const MAX_IDENTITY_PROVIDER_ID_LENGTH = 512;
export declare const MAX_IDENTITY_PROVIDERS_PER_USER = 32;
export declare const MAX_IDENTITY_ROLE_LENGTH = 128;
export declare const normalizeIdentityEmail: (value: unknown) => string;
export declare const validateIdentityProvider: (providerValue: unknown, providerIdValue: unknown) => {
    provider: string;
    providerId: string;
};
export declare const validateIdentityUserId: (value: unknown) => string;
export declare const validateIdentityUser: (value: unknown) => IdentityUser;
//# sourceMappingURL=identityValidation.d.ts.map