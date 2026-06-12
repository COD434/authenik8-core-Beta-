"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.SecurityModule = void 0;
const helmet_1 = __importDefault(require("helmet"));
const ioredis_1 = __importDefault(require("ioredis"));
const rate_limiter_flexible_1 = require("rate-limiter-flexible");
const ip_address_1 = require("ip-address");
const WHITELIST_KEY = "whitelist:ips";
const IP_EXPIRATION_SECONDS = 7 * 24 * 60 * 60;
const DEFAULT_JWT_EXPIRY = "1h";
const whitelistEntryKey = (entry) => `${WHITELIST_KEY}:entry:${encodeURIComponent(entry)}`;
const JWT_SECRET = process.env.JWT_SECRET || "Boo";
const EXPIRY = "1h";
class SecurityModule {
    constructor(options = {}) {
        this.jwtSecret = options.jwtSecret || process.env.JWT_SECRET || "Boo";
        this.jwtExpiry = options.jwtExpiry || DEFAULT_JWT_EXPIRY;
        this.whiteListEnabled = options.whiteListEnabled ?? true;
        this.helmetEnabled = options.helmetEnabled ?? true;
        this.rateLimiterEnabled = options.rateLimiterEnabled ?? true;
        this.trustProxyHeaders = options.trustProxyHeaders ?? false;
        this.redisClient = options.redisClient || new ioredis_1.default({
            host: process.env.REDIS_HOST || "127.0.0.1",
            port: Number(process.env.REDIS_PORT || 6379),
            enableOfflineQueue: false,
            retryStrategy: (times) => Math.min(times * 50, 2000),
            maxRetriesPerRequest: 10,
        });
        if (this.rateLimiterEnabled) {
            this.rateLimiter = new rate_limiter_flexible_1.RateLimiterRedis({
                storeClient: this.redisClient,
                keyPrefix: "rate_limit",
                points: options.rateLimitPoints || 100,
                duration: options.rateLimitDuration || 60,
                blockDuration: options.rateLimitBlock || 300,
            });
        }
        this.redisClient.on("error", () => { });
    }
    async isAllowed(ip) {
        if (!this.whiteListEnabled)
            return true;
        try {
            const exists = await this.redisClient.sismember(WHITELIST_KEY, ip);
            if (exists === 1)
                return true;
            if (ip === "::1" || ip === "127.0.0.1")
                return true;
            const entries = await this.listIPs();
            for (const entry of entries) {
                if (entry.includes("/")) {
                    if (new ip_address_1.Address4(ip).isInSubnet(new ip_address_1.Address4(entry)))
                        return true;
                }
            }
            return false;
        }
        catch {
            return false;
        }
    }
    async addIP(ipOrCIDR, ttl = IP_EXPIRATION_SECONDS) {
        await this.redisClient.sadd(WHITELIST_KEY, ipOrCIDR);
        await this.redisClient.set(whitelistEntryKey(ipOrCIDR), "1", "EX", ttl);
    }
    async removeIP(ipOrCIDR) {
        await this.redisClient.srem(WHITELIST_KEY, ipOrCIDR);
        await this.redisClient.del(whitelistEntryKey(ipOrCIDR));
    }
    async listIPs() {
        const entries = await this.redisClient.smembers(WHITELIST_KEY);
        const activeEntries = [];
        for (const entry of entries) {
            const exists = await this.redisClient.exists(whitelistEntryKey(entry));
            if (exists === 1) {
                activeEntries.push(entry);
            }
            else {
                await this.redisClient.srem(WHITELIST_KEY, entry);
            }
        }
        return activeEntries;
    }
    getClientIp(req) {
        if (this.trustProxyHeaders) {
            const forwarded = req.headers["x-forwarded-for"]?.toString().split(",")[0]?.trim();
            if (forwarded) {
                return forwarded;
            }
        }
        return req.ip || req.socket.remoteAddress || "unknown";
    }
    whiteListMiddleware() {
        return async (req, res, next) => {
            if (!this.whiteListEnabled)
                return next();
            const clientIP = this.getClientIp(req);
            if (await this.isAllowed(clientIP))
                return next();
            res.status(403).json({ error: "Access denied" });
        };
    }
    rateLimiterMiddleware() {
        return (req, res, next) => {
            if (!this.rateLimiter || !this.rateLimiterEnabled)
                return next();
            const ip = req.ip || req.socket.remoteAddress || "unknown";
            this.rateLimiter.consume(ip).then(() => next()).catch(() => res.status(429).send("Too many Requests"));
        };
    }
    helmetMiddleware() {
        if (!this.helmetEnabled) {
            return (req, res, next) => next();
        }
        const helmetDirectives = {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'", "trusted-cdn.com"],
            styleSrc: ["'self'"],
            imgSrc: ["'self'", "data:", "trusted-cdn.com"],
            fontSrc: ["'self'", "trusted-cdn.com"],
            connectSrc: ["'self'", "api.trusted-domain.com"],
            frameSrc: ["'none'"],
            objectSrc: ["'none'"],
            upgradeInsecureRequests: [],
            reportUri: "/csp-violation-report",
        };
        return (0, helmet_1.default)({
            contentSecurityPolicy: {
                directives: helmetDirectives, reportOnly: process.env.NODE_ENV !== "production"
            },
            hsts: { maxAge: 315366000,
                includeSubDomains: true, preload: true },
            xxsFilter: true,
            noSniff: true,
            frameguard: { action: "deny" },
            referrerPolicy: { policy: "same-origin" },
        });
    }
}
exports.SecurityModule = SecurityModule;
//# sourceMappingURL=ipService.js.map