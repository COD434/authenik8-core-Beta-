"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.createRedisOAuthStateStore = void 0;
exports.createOAuth = createOAuth;
const google_1 = require("./providers/google");
const github_1 = require("./providers/github");
const stateKey = (state) => `oauth:state:${state}`;
const createRedisOAuthStateStore = (redisClient) => ({
    async set(state, value, ttlSeconds) {
        await redisClient.setex(stateKey(state), ttlSeconds, JSON.stringify(value));
    },
    async get(state) {
        const stored = await redisClient.get(stateKey(state));
        return stored ? JSON.parse(stored) : null;
    },
    async del(state) {
        await redisClient.del(stateKey(state));
    },
});
exports.createRedisOAuthStateStore = createRedisOAuthStateStore;
function createOAuth(config) {
    const stateStore = config.stateStore ??
        (config.redisClient
            ? (0, exports.createRedisOAuthStateStore)(config.redisClient)
            : undefined);
    if (!config.google && !config.github) {
        return {
            google: undefined,
            github: undefined,
        };
    }
    if (!stateStore) {
        throw new Error("OAuth requires a stateStore or redisClient");
    }
    return {
        google: config.google
            ? (0, google_1.createGoogleProvider)(config.google, stateStore, config.identityEngine)
            : undefined,
        github: config.github
            ? (0, github_1.createGitHubProvider)(config.github, stateStore, config.identityEngine)
            : undefined,
    };
}
//# sourceMappingURL=core.js.map