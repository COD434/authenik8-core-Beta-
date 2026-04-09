import { SignOptions } from "jsonwebtoken";
import { Redis } from "ioredis";
import { OAuthConfig } from "../oauth/types";
export interface Authenik8Config {
    jwtSecret: string;
    jwtExpiry?: SignOptions["expiresIn"];
    refreshSecret: string;
    oauth?: OAuthConfig;
    redis?: Redis;
}
//# sourceMappingURL=config.d.ts.map