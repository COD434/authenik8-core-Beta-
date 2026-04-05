"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const dotenv_1 = __importDefault(require("dotenv"));
const express_1 = __importDefault(require("express"));
const createAuthenik8_1 = require("../createAuthenik8");
dotenv_1.default.config();
const app = (0, express_1.default)();
async function start() {
    const auth = await (0, createAuthenik8_1.createAuthenik8)({
        jwtSecret: "test",
        refreshSecret: "test",
        oauth: {
            google: {
                clientId: process.env.GOOGLE_CLIENT_ID,
                clientSecret: process.env.GOOGLE_CLIENT_SECRET,
                redirectUri: "http://localhost:4000/callback",
            },
        },
    });
    app.get("/auth/google", auth.oauth.google.redirect);
    app.get("/callback", async (req, res) => {
        try {
            const { profile } = await auth.oauth.google.handleCallback(req);
            res.json(profile);
        }
        catch (err) {
            let message = "unknown error";
            if (err instanceof Error) {
                message = err.message;
            }
            console.error("OAuth error:", message);
            res.status(500).json({ error: message
            });
        }
    });
    app.listen(4000, () => {
        console.log("OAuth test server running on http://localhost:4000");
    });
}
start();
//# sourceMappingURL=oauth.test.js.map