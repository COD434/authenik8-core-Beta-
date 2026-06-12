"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.getRedisConfig = exports.validateRedisConfig = exports.initializeRedisClient = exports.setupRedis = void 0;
const dotenv_1 = __importDefault(require("dotenv"));
const connect_redis_1 = require("connect-redis");
const ioredis_1 = __importDefault(require("ioredis"));
dotenv_1.default.config();
let redisClientInstance = null;
let redisStoreInstance = null;
const DEFAULT_REDIS_CONFIG = {
    host: process.env.REDIS_HOST ?? "127.0.0.1",
    port: Number(process.env.REDIS_PORT ?? "6379"),
    maxRetriesPerRequest: 10,
    connectTimeout: 5000
};
const DEFAULT_STORE_OPTIONS = {
    prefix: "session",
    ttl: 86400
};
const validateRedisConfig = (config) => {
    if (!config.url && !config.host) {
        throw new Error("Redis configuration requires either URL or host/port");
    }
    if (config.url && !config.url.startsWith("redis://") && !config.url.startsWith("rediss://")) {
        throw new Error("Redis URL must use 'redis://' protocol");
    }
};
exports.validateRedisConfig = validateRedisConfig;
const getRedisConfig = (options) => {
    const port = options?.port ?
        Number(options.port) :
        process.env.REDIS_PORT ? Number(process.env.REDIS_PORT) :
            Number(DEFAULT_REDIS_CONFIG.port);
    const config = {
        ...DEFAULT_REDIS_CONFIG,
        host: options?.host || process.env.REDIS_HOST || DEFAULT_REDIS_CONFIG.host,
        port: port,
        password: options?.password || process.env.REDIS_PASSWORD || undefined,
        ...options
    };
    validateRedisConfig(config);
    return config;
};
exports.getRedisConfig = getRedisConfig;
const setupRedis = async (options) => {
    try {
        const config = getRedisConfig(options?.redisConfig);
        const storeOptions = { ...DEFAULT_STORE_OPTIONS, ...options?.storeOptions };
        const redisClient = new ioredis_1.default({
            host: config.host,
            port: Number(config.port),
            connectTimeout: config.connectTimeout,
            password: config.password,
            retryStrategy: (times) => Math.min(times * 50, 2000),
            maxRetriesPerRequest: config.maxRetriesPerRequest
        });
        await new Promise((resolve, reject) => {
            redisClient.once("ready", async () => {
                try {
                    await redisClient.ping();
                    resolve();
                }
                catch (err) {
                    reject(err);
                }
            });
            redisClient.once("error", (err) => {
                reject(err);
            });
        });
        const redisStore = new connect_redis_1.RedisStore({
            client: redisClient,
            prefix: storeOptions.prefix,
            ttl: storeOptions.ttl
        });
        redisClient.on("error", () => { });
        redisClient.on("ready", () => { });
        redisClient.on("reconnecting", () => { });
        return { redisClient, redisStore };
    }
    catch (error) {
        throw error;
    }
};
exports.setupRedis = setupRedis;
const initializeRedisClient = async () => {
    if (!redisClientInstance) {
        const { redisClient } = await setupRedis();
        redisClientInstance = redisClient;
    }
    return redisClientInstance;
};
exports.initializeRedisClient = initializeRedisClient;
//# sourceMappingURL=redisService.js.map