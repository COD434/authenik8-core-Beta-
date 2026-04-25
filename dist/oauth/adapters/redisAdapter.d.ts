import type { Redis } from "ioredis";
type ProviderRecord = {
    provider: string;
    providerId: string;
};
type IdentityUser = {
    id: string;
    email: string;
    providers: ProviderRecord[];
};
export interface OAuthIdentityAdapter {
    findUserByEmail(email: string): Promise<IdentityUser | null>;
    findUserByProvider(provider: string, providerId: string): Promise<IdentityUser | null>;
    createUser(data: {
        email: string;
        provider: string;
        providerId: string;
    }): Promise<IdentityUser>;
    linkProvider(userId: string, provider: string, providerId: string): Promise<void>;
}
export declare const createRedisIdentityAdapter: (redis: Redis) => OAuthIdentityAdapter;
export {};
//# sourceMappingURL=redisAdapter.d.ts.map