import { createHash } from "crypto";
import type {
  NextFunction,
  Request,
  RequestHandler,
  Response,
} from "express";
import helmet, { type HelmetOptions } from "helmet";
import type Redis from "ioredis";
import { RateLimiterRedis } from "rate-limiter-flexible";
import type { AuditEmitter } from "../audit/types";
import { validateRedisKeyPrefix } from "../redis/keyNamespace";
import {
  createClientIpResolver,
  isIpInCidr,
  normalizeIp,
  normalizeIpOrCidr,
} from "./requestContext";

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

const positiveInteger = (
  value: number | undefined,
  fallback: number,
  name: string,
  maximum: number,
): number => {
  const resolved = value ?? fallback;
  if (
    !Number.isSafeInteger(resolved) ||
    resolved <= 0 ||
    resolved > maximum
  ) {
    throw new Error(`${name} must be between 1 and ${maximum}`);
  }
  return resolved;
};

const validateBooleanOptions = (options: SecurityOptions): void => {
  const entries: Array<[string, unknown]> = [
    ["rateLimiterEnabled", options.rateLimiterEnabled],
    ["enableRateLimiter", options.enableRateLimiter],
    ["whiteListEnabled", options.whiteListEnabled],
    ["enableWhitelist", options.enableWhitelist],
    ["helmetEnabled", options.helmetEnabled],
    ["enableHelmet", options.enableHelmet],
    ["trustProxyHeaders", options.trustProxyHeaders],
  ];
  const invalid = entries.find(
    ([, value]) => value !== undefined && typeof value !== "boolean",
  );
  if (invalid) {
    throw new Error(`${invalid[0]} must be a boolean`);
  }
  const aliases: Array<[string, boolean | undefined, string, boolean | undefined]> = [
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
  const conflict = aliases.find(
    ([, current, , legacy]) =>
      current !== undefined &&
      legacy !== undefined &&
      current !== legacy,
  );
  if (conflict) {
    throw new Error(`${conflict[0]} conflicts with ${conflict[2]}`);
  }
};

export class SecurityModule {
  private readonly redisClient: Redis;
  private readonly rateLimiter?: RateLimiterRedis;
  private readonly whiteListEnabled: boolean;
  private readonly helmetEnabled: boolean;
  private readonly rateLimiterEnabled: boolean;
  private readonly resolveClientIp: (request: Request) => string;
  private readonly helmetOptions?: HelmetOptions;
  private readonly audit?: AuditEmitter;
  private readonly exactSetKey: string;
  private readonly cidrSetKey: string;
  private readonly entryPrefix: string;

  constructor(options: SecurityOptions = {}) {
    validateBooleanOptions(options);
    this.whiteListEnabled =
      options.whiteListEnabled ?? options.enableWhitelist ?? true;
    this.helmetEnabled =
      options.helmetEnabled ?? options.enableHelmet ?? true;
    this.rateLimiterEnabled =
      options.rateLimiterEnabled ?? options.enableRateLimiter ?? true;
    this.audit = options.audit;
    this.helmetOptions = options.helmetOptions;

    if (
      options.trustProxyHeaders === true &&
      (!options.trustedProxyCidrs || options.trustedProxyCidrs.length === 0)
    ) {
      throw new Error(
        "trustProxyHeaders requires at least one trustedProxyCidrs network",
      );
    }
    this.resolveClientIp = createClientIpResolver(
      options.trustedProxyCidrs ?? [],
    );

    if (!options.redisClient) {
      throw new Error("SecurityModule requires an explicit Redis client");
    }
    this.redisClient = options.redisClient;

    const prefix = validateRedisKeyPrefix(
      options.keyPrefix ?? "authenik8:security",
    );
    const allowlistPrefix = `${prefix}:{allowlist}`;
    this.exactSetKey = `${allowlistPrefix}:exact`;
    this.cidrSetKey = `${allowlistPrefix}:cidr`;
    this.entryPrefix = `${allowlistPrefix}:entry`;

    if (this.rateLimiterEnabled) {
      this.rateLimiter = new RateLimiterRedis({
        storeClient: this.redisClient,
        keyPrefix: `${prefix}:rate-limit`,
        points: positiveInteger(
          options.rateLimitPoints,
          100,
          "rateLimitPoints",
          1_000_000,
        ),
        duration: positiveInteger(
          options.rateLimitDuration,
          60,
          "rateLimitDuration",
          MAX_IP_EXPIRATION_SECONDS,
        ),
        blockDuration: positiveInteger(
          options.rateLimitBlock,
          300,
          "rateLimitBlock",
          MAX_IP_EXPIRATION_SECONDS,
        ),
      });
    }
    this.redisClient.on("error", () => {});
  }

  private entryKey(entry: string): string {
    const id = createHash("sha256").update(entry).digest("base64url");
    return `${this.entryPrefix}:${id}`;
  }

  private async activeEntries(
    setKey: string,
    entries: readonly string[],
  ): Promise<string[]> {
    if (entries.length === 0) return [];
    const active: string[] = [];
    const expired: string[] = [];
    for (
      let offset = 0;
      offset < entries.length;
      offset += REDIS_ENTRY_BATCH_SIZE
    ) {
      const batch = entries.slice(offset, offset + REDIS_ENTRY_BATCH_SIZE);
      const markers = await this.redisClient.mget(
        ...batch.map((entry) => this.entryKey(entry)),
      );
      batch.forEach((entry, index) => {
        if (markers[index] !== null) active.push(entry);
        else expired.push(entry);
      });
    }
    if (expired.length > 0) {
      for (
        let offset = 0;
        offset < expired.length;
        offset += REDIS_ENTRY_BATCH_SIZE
      ) {
        await this.redisClient.srem(
          setKey,
          ...expired.slice(offset, offset + REDIS_ENTRY_BATCH_SIZE),
        );
      }
    }
    return active;
  }

  async isAllowed(ip: string): Promise<boolean> {
    if (!this.whiteListEnabled) return true;
    const normalizedIp = normalizeIp(ip);
    if (!normalizedIp) return false;

    try {
      const exactAllowed = Number(
        await this.redisClient.eval(
          EXACT_ALLOW_SCRIPT,
          2,
          this.exactSetKey,
          this.entryKey(normalizedIp),
          normalizedIp,
        ),
      );
      if (exactAllowed === 1) return true;

      const cidrs = await this.redisClient.smembers(this.cidrSetKey);
      const activeCidrs = await this.activeEntries(this.cidrSetKey, cidrs);
      return activeCidrs.some((cidr) => isIpInCidr(normalizedIp, cidr));
    } catch {
      return false;
    }
  }

  async addIP(
    ipOrCIDR: string,
    ttl: number = IP_EXPIRATION_SECONDS,
  ): Promise<void> {
    const entry = normalizeIpOrCidr(ipOrCIDR);
    if (!entry) throw new Error("Invalid IP address or CIDR");
    if (
      !Number.isSafeInteger(ttl) ||
      ttl <= 0 ||
      ttl > MAX_IP_EXPIRATION_SECONDS
    ) {
      throw new Error(
        `IP allowlist TTL must be between 1 and ${MAX_IP_EXPIRATION_SECONDS} seconds`,
      );
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

  async removeIP(ipOrCIDR: string): Promise<void> {
    const entry = normalizeIpOrCidr(ipOrCIDR);
    if (!entry) throw new Error("Invalid IP address or CIDR");
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

  async listIPs(): Promise<string[]> {
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

  whiteListMiddleware(): RequestHandler {
    return async (req: Request, res: Response, next: NextFunction) => {
      if (!this.whiteListEnabled) return next();
      const clientIp = this.resolveClientIp(req);

      if (await this.isAllowed(clientIp)) return next();
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

  rateLimiterMiddleware(): RequestHandler {
    return async (req: Request, res: Response, next: NextFunction) => {
      if (!this.rateLimiter || !this.rateLimiterEnabled) return next();
      const ip = this.resolveClientIp(req);
      try {
        await this.rateLimiter.consume(ip);
        return next();
      } catch (error) {
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

  helmetMiddleware(): RequestHandler {
    if (!this.helmetEnabled) {
      return (_req: Request, _res: Response, next: NextFunction) => next();
    }
    if (this.helmetOptions) return helmet(this.helmetOptions);

    return helmet({
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
        maxAge: 63_072_000,
        includeSubDomains: true,
        preload: true,
      },
      noSniff: true,
      frameguard: { action: "deny" },
      referrerPolicy: { policy: "no-referrer" },
    });
  }
}

const isRateLimiterRejection = (
  value: unknown,
): value is {
  msBeforeNext: number;
  remainingPoints: number;
  consumedPoints: number;
} => {
  if (!value || typeof value !== "object") return false;
  const candidate = value as {
    msBeforeNext?: unknown;
    remainingPoints?: unknown;
    consumedPoints?: unknown;
  };
  return (
    typeof candidate.msBeforeNext === "number" &&
    Number.isFinite(candidate.msBeforeNext) &&
    candidate.msBeforeNext >= 0 &&
    typeof candidate.remainingPoints === "number" &&
    Number.isFinite(candidate.remainingPoints) &&
    typeof candidate.consumedPoints === "number" &&
    Number.isFinite(candidate.consumedPoints) &&
    candidate.consumedPoints >= 0
  );
};
