import type { IdentityUser, OAuthIdentityAdapter } from "../types";
type MemoryIdentityAdapter = OAuthIdentityAdapter & {
    reset(): void;
    dump(): IdentityUser[];
};
export declare const memoryAdapter: MemoryIdentityAdapter;
export {};
//# sourceMappingURL=memoryAdapter.d.ts.map