"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.createOAuth = createOAuth;
const google_1 = require("./providers/google");
const github_1 = require("./providers/github");
function createOAuth(config) {
    return {
        google: config.google
            ? (0, google_1.createGoogleProvider)(config.google, config.redisClient, config.identityEngine)
            : undefined,
        github: config.github
            ? (0, github_1.createGitHubProvider)(config.github, config.redisClient, config.identityEngine)
            : undefined,
    };
}
//# sourceMappingURL=core.js.map