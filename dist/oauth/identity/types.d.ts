export type IdentityState = "EXISTING_PROVIDER_LOGIN" | "EXISTING_EMAIL_CONFLICT" | "NEW_USER_CREATION" | "LINK_PROVIDER" | "INVALID_LINK_REQUEST";
export type IdentityContext = {
    email: string;
    provider: string;
    providerId: string;
    mode: "login" | "link";
    userId?: string;
};
export type IdentityResult = {
    type: "EXISTING_PROVIDER_LOGIN";
    user: any;
    accessToken: string;
    refreshToken: string;
} | {
    type: "EXISTING_EMAIL_CONFLICT";
    email: string;
    user: any;
    message: string;
} | {
    type: "NEW_USER_CREATION";
    user: any;
    accessToken: string;
    refreshToken: string;
} | {
    type: "LINK_PROVIDER";
    success: true;
    user: any;
} | {
    type: "INVALID_LINK_REQUEST";
    message: string;
};
//# sourceMappingURL=types.d.ts.map