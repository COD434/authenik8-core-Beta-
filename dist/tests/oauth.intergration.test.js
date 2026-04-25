"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const supertest_1 = __importDefault(require("supertest"));
const express_1 = __importDefault(require("express"));
const createAuthenik8_1 = require("../createAuthenik8");
test("OAuth callback issues tokens", async () => {
    const app = (0, express_1.default)();
    const auth = await (0, createAuthenik8_1.createAuthenik8)({
        jwtSecret: "test",
        refreshSecret: "test",
    });
    // 🔥 Mock OAuth provider
    auth.oauth = {
        google: {
            handleCallback: async () => ({
                profile: {
                    email: "test@example.com",
                    name: "Test User",
                    provider: "google",
                    providerId: "123",
                },
            }),
        },
    };
    app.get("/callback", async (req, res) => {
        const { profile } = await auth.oauth.google.handleCallback(req);
        const tokens = await auth.issueTokensFromProfile(profile);
        res.json(tokens);
    });
    const res = await (0, supertest_1.default)(app).get("/callback");
    expect(res.status).toBe(200);
    expect(res.body.accessToken).toBeDefined();
    expect(res.body.refreshToken).toBeDefined();
});
//# sourceMappingURL=oauth.intergration.test.js.map