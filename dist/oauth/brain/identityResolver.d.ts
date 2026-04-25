import { OAuthProfile } from "../types";
export declare function resolveIdentity(profile: OAuthProfile): Promise<import("../userStore").User | {
    type: string;
    user: import("../userStore").User;
    message: string;
}>;
//# sourceMappingURL=identityResolver.d.ts.map