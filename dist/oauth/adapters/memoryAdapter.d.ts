type Provider = {
    provider: string;
    providerId: string;
};
type User = {
    id: string;
    email: string;
    providers: Provider[];
};
export declare const memoryAdapter: {
    findUserByEmail(email: string): Promise<User | null>;
    findUserByProvider(provider: string, providerId: string): Promise<User | null>;
    createUser(data: {
        email: string;
        provider: string;
        providerId: string;
    }): Promise<User>;
    linkProvider(userId: string, provider: string, providerId: string): Promise<void>;
    reset(): void;
    dump(): User[];
};
export {};
//# sourceMappingURL=memoryAdapter.d.ts.map