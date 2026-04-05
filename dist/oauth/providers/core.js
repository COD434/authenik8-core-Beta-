"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.createOAuth = createOAuth;
const google_1 = require("./google");
function createOAuth(config) {
    return {
        google: config.google
            ? (0, google_1.createGoogleProvider)(config.google)
            : undefined,
    };
}
//# sourceMappingURL=core.js.map