export interface IdentityPolicy {
    readonly autoLinkOnVerifiedEmailMatch: boolean;
    readonly allowUnverifiedAutoLink: boolean;
}
export type IdentityPolicyConfig = Partial<IdentityPolicy>;
export declare const identityPolicy: IdentityPolicy;
export declare const resolveIdentityPolicy: (configured?: IdentityPolicyConfig) => IdentityPolicy;
//# sourceMappingURL=identityPolicy.d.ts.map