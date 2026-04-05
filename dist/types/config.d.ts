import { SignOptions } from "jsonwebtoken";
import { Redis } from "ioredis";
import { GoogleOAuthConfig } from "../oauth/providers/types";
export interface Authenik8Config {
    jwtSecret: string;
    jwtExpiry?: SignOptions["expiresIn"];
    refreshSecret: string;
    oauth?: {
        google?: GoogleOAuthConfig;
    };
    redis?: Redis;
}
//# sourceMappingURL=config.d.ts.map