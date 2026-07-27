import type { RequestHandler } from "express";
import { type HelmetOptions } from "helmet";
import type Redis from "ioredis";
import type { AuditEmitter } from "../audit/types";
export interface SecurityOptions {
    redisClient?: Redis;
    rateLimitPoints?: number;
    rateLimitDuration?: number;
    rateLimitBlock?: number;
    rateLimiterEnabled?: boolean;
    enableWhitelist?: boolean;
    enableRateLimiter?: boolean;
    enableHelmet?: boolean;
    whiteListEnabled?: boolean;
    helmetEnabled?: boolean;
    /**
     * @deprecated Forwarding headers require `trustedProxyCidrs`; a blanket
     * boolean trust setting is rejected.
     */
    trustProxyHeaders?: boolean;
    trustedProxyCidrs?: readonly string[];
    helmetOptions?: HelmetOptions;
    audit?: AuditEmitter;
    keyPrefix?: string;
}
export declare class SecurityModule {
    private readonly redisClient;
    private readonly rateLimiter?;
    private readonly whiteListEnabled;
    private readonly helmetEnabled;
    private readonly rateLimiterEnabled;
    private readonly resolveClientIp;
    private readonly helmetOptions?;
    private readonly audit?;
    private readonly exactSetKey;
    private readonly cidrSetKey;
    private readonly entryPrefix;
    constructor(options?: SecurityOptions);
    private entryKey;
    private activeEntries;
    isAllowed(ip: string): Promise<boolean>;
    addIP(ipOrCIDR: string, ttl?: number): Promise<void>;
    removeIP(ipOrCIDR: string): Promise<void>;
    listIPs(): Promise<string[]>;
    whiteListMiddleware(): RequestHandler;
    rateLimiterMiddleware(): RequestHandler;
    helmetMiddleware(): RequestHandler;
}
//# sourceMappingURL=ipService.d.ts.map