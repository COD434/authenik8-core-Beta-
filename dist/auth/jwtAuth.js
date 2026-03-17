"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.JWTService = void 0;
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
//import {setupRedis} from "./redis";
//import {guestCounter, guestBlocked} from "./Monitor/monitor";
const crypto_1 = __importDefault(require("crypto"));
class JWTService {
    //constructor(secret: string, expiry:SignOptions["expiresIn"]){
    //this.secret = secret
    //this.expiry = expiry
    //}
    signToken(payload) {
        return jsonwebtoken_1.default.sign(payload, this.secret, {
            expiresIn: this.expiry
        });
    }
    ;
    constructor(options) {
        this.authenticateJWT = async (req, res, next) => {
            var _a;
            const authHeader = req.headers.authorization;
            const token = ((_a = req.cookies) === null || _a === void 0 ? void 0 : _a.token) || ((authHeader === null || authHeader === void 0 ? void 0 : authHeader.startsWith("Bearer")) ? authHeader.split(" ")[1] : null);
            if (!token) {
                return res.status(401).json({ message: "Unauthorized" });
            }
            try {
                const decoded = jsonwebtoken_1.default.verify(token, this.secret);
                if (this.redisclient && decoded.userId) {
                    const storedToken = await this.redisclient.get(`session:${decoded.userId}`);
                    if (storedToken !== token) {
                        return res
                            .status(403)
                            .json({ success: false, message: "invalid session", errors: [] });
                    }
                }
                req.user = decoded;
                next();
            }
            catch {
                return res.status(403)
                    .json({ success: false, message: "invalid or expired token" });
            }
        };
        this.secret = options.secret;
        this.expiry = options.expiry;
        this.redisclient = options.redisClient;
        this.onGuestToken = options.onGuestToken;
    }
    guestToken() {
        const payload = {
            type: "guest",
            id: crypto_1.default.randomUUID(),
            createdAt: Date.now
        };
        if (this.onGuestToken)
            this.onGuestToken();
        return jsonwebtoken_1.default.sign(payload, this.secret, { expiresIn: this.expiry });
    }
    verifyToken(token) {
        try {
            return jsonwebtoken_1.default.verify(token, this.secret);
        }
        catch {
            return null;
        }
    }
}
exports.JWTService = JWTService;
//const redisClientPromise = setupRedis();
//let redisClient:any;
//redisClientPromise.then(({redisClient: client}) =>{
//redisClient = client;
//}).catch (err => console.error("Redis setup error",err));
//const T_EXPIRY = "1d"
//export const guestToken = (): string =>{
//const Payload={
//type: "guest",
//id:crypto.randomUUID(),
//createdAt:Date.now
//}
//if(guestToken()){
//guestCounter.inc();
//return jwt.sign(Payload,process.env.JWT_SECRET!,{expiresIn:T_EXPIRY});
//}
//export const verifyToken = (token:string): any | null=>{
//try{
//jwt.verify(token,process.env.JWT_SECRET!);
//}catch{
//return null;
//}
//} 
//export const authenticateJWT = async(req:Request, res:Response, next:NextFunction): Promise<void> =>{
//	const authHeader = req.headers.authorization;
//const token = req.cookies?.token ||(authHeader?.startsWith("Bearer ") ? authHeader.split(" ")[1] : null);
//if (!token){
//res.status(401).json({message: "Unauthorized"})
//return;
//}
//try{
//const decoded = jwt.verify(token, process.env.JWT_SECRET!) as JwtPayload
//const storedToken = await redisClient.get(`session:${decoded.userId}`);
//if(storedToken !== token){
//res.status(403).json({success:false, message: "Invalid session", errors:[]})
//return
//}
//(req as any).user = decoded;
//return next()
//}catch(err){
//res.status(403).json({success: false ,message: "Invalid  or expired token"})
//return
//};
//}
//# sourceMappingURL=jwtAuth.js.map