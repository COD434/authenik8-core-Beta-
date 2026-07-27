"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.createRedisOAuthStateStore = void 0;
exports.createOAuth = createOAuth;
const google_1 = require("./providers/google");
const github_1 = require("./providers/github");
const keyNamespace_1 = require("../redis/keyNamespace");
const state_1 = require("./state");
const TAKE_STATE_SCRIPT = `
local value = redis.call("GET", KEYS[1])
if value then
  redis.call("DEL", KEYS[1])
end
return value
`;
const stateKey = (keyPrefix, state) => `${keyPrefix}:state:${state}`;
const createRedisOAuthStateStore = (redisClient, keyPrefix = "oauth") => {
    if (!redisClient.getdel && !redisClient.eval) {
        throw new Error("OAuth Redis state requires atomic GETDEL or EVAL support");
    }
    const prefix = (0, keyNamespace_1.validateRedisKeyPrefix)(keyPrefix);
    return {
        async set(state, value, ttlSeconds) {
            if (!(0, state_1.isValidOAuthStateToken)(state)) {
                throw new Error("OAuth state must be a 256-bit lower-case hexadecimal value");
            }
            if (!(0, state_1.isValidOAuthState)(value)) {
                throw new Error("OAuth state payload is invalid");
            }
            if (!Number.isSafeInteger(ttlSeconds) ||
                ttlSeconds <= 0 ||
                ttlSeconds > state_1.OAUTH_STATE_TTL_SECONDS) {
                throw new Error(`OAuth state TTL must be between 1 and ${state_1.OAUTH_STATE_TTL_SECONDS} seconds`);
            }
            await redisClient.setex(stateKey(prefix, state), ttlSeconds, JSON.stringify(value));
        },
        async get(state) {
            if (!(0, state_1.isValidOAuthStateToken)(state))
                return null;
            const stored = await redisClient.get(stateKey(prefix, state));
            return stored ? (0, state_1.parseOAuthState)(stored) : null;
        },
        async del(state) {
            if (!(0, state_1.isValidOAuthStateToken)(state))
                return;
            await redisClient.del(stateKey(prefix, state));
        },
        async take(state) {
            if (!(0, state_1.isValidOAuthStateToken)(state))
                return null;
            const key = stateKey(prefix, state);
            const stored = redisClient.getdel
                ? await redisClient.getdel(key)
                : (await redisClient.eval(TAKE_STATE_SCRIPT, 1, key));
            return stored ? (0, state_1.parseOAuthState)(stored) : null;
        },
    };
};
exports.createRedisOAuthStateStore = createRedisOAuthStateStore;
function createOAuth(config) {
    const stateStore = config.stateStore ??
        (config.redisClient
            ? (0, exports.createRedisOAuthStateStore)(config.redisClient, config.keyPrefix)
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
    if (typeof stateStore.set !== "function" ||
        typeof stateStore.take !== "function") {
        throw new Error("OAuth stateStore must implement set() and atomic take()");
    }
    return {
        google: config.google
            ? (0, google_1.createGoogleProvider)(config.google, stateStore, config.identityEngine, config.audit)
            : undefined,
        github: config.github
            ? (0, github_1.createGitHubProvider)(config.github, stateStore, config.identityEngine, config.audit)
            : undefined,
    };
}
//# sourceMappingURL=core.js.map