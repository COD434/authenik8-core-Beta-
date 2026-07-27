"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.SecurityModule = void 0;
const crypto_1 = require("crypto");
const helmet_1 = __importDefault(require("helmet"));
const rate_limiter_flexible_1 = require("rate-limiter-flexible");
const keyNamespace_1 = require("../redis/keyNamespace");
const requestContext_1 = require("./requestContext");
const IP_EXPIRATION_SECONDS = 7 * 24 * 60 * 60;
const MAX_IP_EXPIRATION_SECONDS = 366 * 24 * 60 * 60;
const REDIS_ENTRY_BATCH_SIZE = 500;
const EXACT_ALLOW_SCRIPT = `
if redis.call("SISMEMBER", KEYS[1], ARGV[1]) == 0 then
  return 0
end
if redis.call("EXISTS", KEYS[2]) == 1 then
  return 1
end
redis.call("SREM", KEYS[1], ARGV[1])
return 0
`;
const positiveInteger = (value, fallback, name, maximum) => {
    const resolved = value ?? fallback;
    if (!Number.isSafeInteger(resolved) ||
        resolved <= 0 ||
        resolved > maximum) {
        throw new Error(`${name} must be between 1 and ${maximum}`);
    }
    return resolved;
};
const validateBooleanOptions = (options) => {
    const entries = [
        ["rateLimiterEnabled", options.rateLimiterEnabled],
        ["enableRateLimiter", options.enableRateLimiter],
        ["whiteListEnabled", options.whiteListEnabled],
        ["enableWhitelist", options.enableWhitelist],
        ["helmetEnabled", options.helmetEnabled],
        ["enableHelmet", options.enableHelmet],
        ["trustProxyHeaders", options.trustProxyHeaders],
    ];
    const invalid = entries.find(([, value]) => value !== undefined && typeof value !== "boolean");
    if (invalid) {
        throw new Error(`${invalid[0]} must be a boolean`);
    }
    const aliases = [
        [
            "rateLimiterEnabled",
            options.rateLimiterEnabled,
            "enableRateLimiter",
            options.enableRateLimiter,
        ],
        [
            "whiteListEnabled",
            options.whiteListEnabled,
            "enableWhitelist",
            options.enableWhitelist,
        ],
        [
            "helmetEnabled",
            options.helmetEnabled,
            "enableHelmet",
            options.enableHelmet,
        ],
    ];
    const conflict = aliases.find(([, current, , legacy]) => current !== undefined &&
        legacy !== undefined &&
        current !== legacy);
    if (conflict) {
        throw new Error(`${conflict[0]} conflicts with ${conflict[2]}`);
    }
};
class SecurityModule {
    constructor(options = {}) {
        validateBooleanOptions(options);
        this.whiteListEnabled =
            options.whiteListEnabled ?? options.enableWhitelist ?? true;
        this.helmetEnabled =
            options.helmetEnabled ?? options.enableHelmet ?? true;
        this.rateLimiterEnabled =
            options.rateLimiterEnabled ?? options.enableRateLimiter ?? true;
        this.audit = options.audit;
        this.helmetOptions = options.helmetOptions;
        if (options.trustProxyHeaders === true &&
            (!options.trustedProxyCidrs || options.trustedProxyCidrs.length === 0)) {
            throw new Error("trustProxyHeaders requires at least one trustedProxyCidrs network");
        }
        this.resolveClientIp = (0, requestContext_1.createClientIpResolver)(options.trustedProxyCidrs ?? []);
        if (!options.redisClient) {
            throw new Error("SecurityModule requires an explicit Redis client");
        }
        this.redisClient = options.redisClient;
        const prefix = (0, keyNamespace_1.validateRedisKeyPrefix)(options.keyPrefix ?? "authenik8:security");
        const allowlistPrefix = `${prefix}:{allowlist}`;
        this.exactSetKey = `${allowlistPrefix}:exact`;
        this.cidrSetKey = `${allowlistPrefix}:cidr`;
        this.entryPrefix = `${allowlistPrefix}:entry`;
        if (this.rateLimiterEnabled) {
            this.rateLimiter = new rate_limiter_flexible_1.RateLimiterRedis({
                storeClient: this.redisClient,
                keyPrefix: `${prefix}:rate-limit`,
                points: positiveInteger(options.rateLimitPoints, 100, "rateLimitPoints", 1000000),
                duration: positiveInteger(options.rateLimitDuration, 60, "rateLimitDuration", MAX_IP_EXPIRATION_SECONDS),
                blockDuration: positiveInteger(options.rateLimitBlock, 300, "rateLimitBlock", MAX_IP_EXPIRATION_SECONDS),
            });
        }
        this.redisClient.on("error", () => { });
    }
    entryKey(entry) {
        const id = (0, crypto_1.createHash)("sha256").update(entry).digest("base64url");
        return `${this.entryPrefix}:${id}`;
    }
    async activeEntries(setKey, entries) {
        if (entries.length === 0)
            return [];
        const active = [];
        const expired = [];
        for (let offset = 0; offset < entries.length; offset += REDIS_ENTRY_BATCH_SIZE) {
            const batch = entries.slice(offset, offset + REDIS_ENTRY_BATCH_SIZE);
            const markers = await this.redisClient.mget(...batch.map((entry) => this.entryKey(entry)));
            batch.forEach((entry, index) => {
                if (markers[index] !== null)
                    active.push(entry);
                else
                    expired.push(entry);
            });
        }
        if (expired.length > 0) {
            for (let offset = 0; offset < expired.length; offset += REDIS_ENTRY_BATCH_SIZE) {
                await this.redisClient.srem(setKey, ...expired.slice(offset, offset + REDIS_ENTRY_BATCH_SIZE));
            }
        }
        return active;
    }
    async isAllowed(ip) {
        if (!this.whiteListEnabled)
            return true;
        const normalizedIp = (0, requestContext_1.normalizeIp)(ip);
        if (!normalizedIp)
            return false;
        try {
            const exactAllowed = Number(await this.redisClient.eval(EXACT_ALLOW_SCRIPT, 2, this.exactSetKey, this.entryKey(normalizedIp), normalizedIp));
            if (exactAllowed === 1)
                return true;
            const cidrs = await this.redisClient.smembers(this.cidrSetKey);
            const activeCidrs = await this.activeEntries(this.cidrSetKey, cidrs);
            return activeCidrs.some((cidr) => (0, requestContext_1.isIpInCidr)(normalizedIp, cidr));
        }
        catch {
            return false;
        }
    }
    async addIP(ipOrCIDR, ttl = IP_EXPIRATION_SECONDS) {
        const entry = (0, requestContext_1.normalizeIpOrCidr)(ipOrCIDR);
        if (!entry)
            throw new Error("Invalid IP address or CIDR");
        if (!Number.isSafeInteger(ttl) ||
            ttl <= 0 ||
            ttl > MAX_IP_EXPIRATION_SECONDS) {
            throw new Error(`IP allowlist TTL must be between 1 and ${MAX_IP_EXPIRATION_SECONDS} seconds`);
        }
        const setKey = entry.includes("/") ? this.cidrSetKey : this.exactSetKey;
        await this.redisClient
            .multi()
            .sadd(setKey, entry)
            .set(this.entryKey(entry), "1", "EX", ttl)
            .exec();
        await this.audit?.emit({
            type: "security.ip_added",
            severity: "warning",
            outcome: "success",
            actor: { type: "system" },
            metadata: { entry, ttl },
        });
    }
    async removeIP(ipOrCIDR) {
        const entry = (0, requestContext_1.normalizeIpOrCidr)(ipOrCIDR);
        if (!entry)
            throw new Error("Invalid IP address or CIDR");
        const setKey = entry.includes("/") ? this.cidrSetKey : this.exactSetKey;
        await this.redisClient
            .multi()
            .srem(setKey, entry)
            .del(this.entryKey(entry))
            .exec();
        await this.audit?.emit({
            type: "security.ip_removed",
            severity: "warning",
            outcome: "success",
            actor: { type: "system" },
            metadata: { entry },
        });
    }
    async listIPs() {
        const [exactEntries, cidrEntries] = await Promise.all([
            this.redisClient.smembers(this.exactSetKey),
            this.redisClient.smembers(this.cidrSetKey),
        ]);
        const [activeExact, activeCidrs] = await Promise.all([
            this.activeEntries(this.exactSetKey, exactEntries),
            this.activeEntries(this.cidrSetKey, cidrEntries),
        ]);
        return [...activeExact, ...activeCidrs].sort();
    }
    whiteListMiddleware() {
        return async (req, res, next) => {
            if (!this.whiteListEnabled)
                return next();
            const clientIp = this.resolveClientIp(req);
            if (await this.isAllowed(clientIp))
                return next();
            await this.audit?.emit({
                type: "security.ip_denied",
                severity: "warning",
                outcome: "denied",
                actor: { type: "unknown" },
                metadata: { ip: clientIp },
            });
            return res.status(403).json({ error: "Access denied" });
        };
    }
    rateLimiterMiddleware() {
        return async (req, res, next) => {
            if (!this.rateLimiter || !this.rateLimiterEnabled)
                return next();
            const ip = this.resolveClientIp(req);
            try {
                await this.rateLimiter.consume(ip);
                return next();
            }
            catch (error) {
                if (!isRateLimiterRejection(error)) {
                    return res
                        .status(503)
                        .send("Security rate limiter unavailable");
                }
                await this.audit?.emit({
                    type: "security.rate_limited",
                    severity: "warning",
                    outcome: "denied",
                    actor: { type: "unknown" },
                    metadata: { ip },
                });
                return res.status(429).send("Too many Requests");
            }
        };
    }
    helmetMiddleware() {
        if (!this.helmetEnabled) {
            return (_req, _res, next) => next();
        }
        if (this.helmetOptions)
            return (0, helmet_1.default)(this.helmetOptions);
        return (0, helmet_1.default)({
            contentSecurityPolicy: {
                directives: {
                    defaultSrc: ["'self'"],
                    scriptSrc: ["'self'"],
                    styleSrc: ["'self'"],
                    imgSrc: ["'self'", "data:"],
                    fontSrc: ["'self'"],
                    connectSrc: ["'self'"],
                    frameAncestors: ["'none'"],
                    objectSrc: ["'none'"],
                    baseUri: ["'self'"],
                    formAction: ["'self'"],
                    upgradeInsecureRequests: [],
                },
            },
            hsts: {
                maxAge: 63072000,
                includeSubDomains: true,
                preload: true,
            },
            noSniff: true,
            frameguard: { action: "deny" },
            referrerPolicy: { policy: "no-referrer" },
        });
    }
}
exports.SecurityModule = SecurityModule;
const isRateLimiterRejection = (value) => {
    if (!value || typeof value !== "object")
        return false;
    const candidate = value;
    return (typeof candidate.msBeforeNext === "number" &&
        Number.isFinite(candidate.msBeforeNext) &&
        candidate.msBeforeNext >= 0 &&
        typeof candidate.remainingPoints === "number" &&
        Number.isFinite(candidate.remainingPoints) &&
        typeof candidate.consumedPoints === "number" &&
        Number.isFinite(candidate.consumedPoints) &&
        candidate.consumedPoints >= 0);
};
//# sourceMappingURL=ipService.js.map