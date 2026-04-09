export type Provider = "google" | "github";
export type User = {
    id: string;
    email: string;
    role?: string;
    providers: {
        provider: Provider;
        providerId: string;
    }[];
};
export declare function findUserByEmail(email: string): Promise<User | undefined>;
export declare function findUserByProvider(provider: Provider, providerId: string): Promise<User | undefined>;
export declare function createUser(data: {
    email: string;
    provider: Provider;
    providerId: string;
}): Promise<User>;
export declare function linkProvider(userId: string, provider: Provider, providerId: string): Promise<void>;
//# sourceMappingURL=userStore.d.ts.map