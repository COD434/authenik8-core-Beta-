"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.RefreshService = exports.InvalidTokenError = exports.MissingTokenError = void 0;
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
class MissingTokenError extends Error {
    constructor(message = "Missing Token") {
        super(message);
        this.name = "MissingTokenError";
    }
}
exports.MissingTokenError = MissingTokenError;
class InvalidTokenError extends Error {
    constructor(message = "Invalid refresh token") {
        super(message);
        this.name = "InvalidTokenError";
    }
}
exports.InvalidTokenError = InvalidTokenError;
class RefreshService {
    constructor(options) {
        var _a, _b, _c;
        this.redisClient = options.redisClient;
        this.accessTokenSecret = options.accessTokenSecret;
        this.refreshTokenSecret = options.refreshTokenSecret;
        this.accessTokenExpiry = (_a = options.accessTokenExpiry) !== null && _a !== void 0 ? _a : "15m";
        this.rotateRefreshTokens = (_b = options.rotateRefreshTokens) !== null && _b !== void 0 ? _b : false;
        this.refreshTokenExpiry = (_c = options.refreshTokenExpiry) !== null && _c !== void 0 ? _c : "7d";
    }
    async refresh(refreshToken) {
        if (!refreshToken) {
            throw new MissingTokenError();
        }
        let decoded;
        try {
            decoded = jsonwebtoken_1.default.verify(refreshToken, this.refreshTokenSecret);
        }
        catch (err) {
            throw new InvalidTokenError();
        }
        const storedToken = await this.redisClient.get(`refresh:${decoded.userId}`);
        if (storedToken !== refreshToken) {
            throw new InvalidTokenError();
        }
        let newRefreshToken;
        if (this.rotateRefreshTokens && this.redisClient.set && this.redisClient.del) {
            await this.redisClient.del(`refresh:${decoded.userId}`);
            newRefreshToken = jsonwebtoken_1.default.sign({ userId: decoded.userId, email: decoded.email }, this.refreshTokenSecret, { expiresIn: this.refreshTokenExpiry });
            await this.redisClient.set(`refresh:${decoded.userId}`, newRefreshToken);
        }
        const newAccessToken = jsonwebtoken_1.default.sign({
            userId: decoded.userId,
            email: decoded.email
        }, this.accessTokenSecret, { expiresIn: this.accessTokenExpiry });
        return {
            accessToken: newAccessToken,
            refreshToken: newRefreshToken,
        };
    }
}
exports.RefreshService = RefreshService;
//export class RefreshService{
//constructor(
//private validateAndRefreshToken:(token:string) => Promise<string//>)//{}
//async refresh(refreshToken?:string){
//if(!refreshToken){
//throw new Error("Missing Token")
//}
//return await this.validateAndRefreshToken(refreshToken);
// }
//}
//# sourceMappingURL=refreshService.js.map