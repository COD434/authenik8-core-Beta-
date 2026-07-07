export type TokenPayload = {
    email: string;
    role?: string;
    userId: string;
    sessionId?: string;
};
export type TokenPair = {
    accessToken: Promise<string> | string;
    refreshToken: string;
};
//# sourceMappingURL=tokens.d.ts.map