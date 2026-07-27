export type TokenPayload = {
    email: string;
    role?: string;
    roles?: string[];
    permissions?: string[];
    scopes?: string[];
    scope?: string;
    tenantId?: string;
    tenantIds?: string[];
    userId: string;
    sessionId?: string;
};
export type TokenPair = {
    accessToken: string;
    refreshToken: string;
};
//# sourceMappingURL=tokens.d.ts.map