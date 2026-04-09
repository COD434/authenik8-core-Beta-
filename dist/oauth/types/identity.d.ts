export type Provider = "google" | "github";
export type Identity = {
    provider: Provider;
    providerId: string;
    email?: string;
    verified: boolean;
};
export type User = {
    userId: string;
    email: string;
    emailVerified: boolean;
    providers: Identity[];
    createdAt: number;
    lastLoginAt?: number;
};
//# sourceMappingURL=identity.d.ts.map