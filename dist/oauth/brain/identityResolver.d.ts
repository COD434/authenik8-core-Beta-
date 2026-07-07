import { OAuthProfile } from "../types";
export declare function resolveIdentity(profile: OAuthProfile): Promise<import("../types").User | {
    type: string;
    user: import("../types").User;
    message: string;
}>;
//# sourceMappingURL=identityResolver.d.ts.map