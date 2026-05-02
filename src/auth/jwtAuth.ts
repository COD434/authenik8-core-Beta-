
import {Request, Response, NextFunction} from "express";
import jwt from "jsonwebtoken";
import { SignOptions } from "jsonwebtoken"
import crypto from "crypto"


interface JwtPayload {
userId: string;
email: string;
type?:string;
id?:string;
createdAt?:number;
}

interface SessionMetadata {
  sessionId: string;
  device: string;
  ip: string;
  createdAt: number;
}

export interface JWTOptions{
jwtSecret:string;
expiry?:SignOptions["expiresIn"];
redisClient?:any;
onGuestToken?: () => void;
}
export class JWTService{

private jwtSecret:string;
private expiry?:SignOptions["expiresIn"]

private redisclient?:any;
private onGuestToken?: () => void;


constructor(options:JWTOptions){
this.jwtSecret = options.jwtSecret;
this.expiry = options.expiry;
this.redisclient = options.redisClient;
this.onGuestToken = options.onGuestToken;

}
async listSessions(userId: string) {
	if (!this.redisclient) return [];
  const sessions = await this.redisclient.hgetall(`sessions:${userId}`);
  return Object.values(sessions || {}).map((s: any) => {
    const { token, ...meta } = JSON.parse(s);
    return meta;
  });
}

async revokeAllSessions(userId: string): Promise<void> {
  if (!this.redisclient) return;
  await this.redisclient.del(`sessions:${userId}`);
}

async revokeSession(userId: string, sessionId: string) {
  await this.redisclient.hdel(`sessions:${userId}`, sessionId);
}

private async persistSessionToken(payload: object, token: string, meta:SessionMetadata){
if (!this.redisclient) return;

const userId = (payload as { userId?: string }).userId;
if (!userId) return;
try{
const decoded = jwt.decode(token) as { exp?: number } | null;
const now = Math.floor(Date.now() / 1000);
const ttl = decoded?.exp ? Math.max(decoded.exp - now, 1) : 3600;

await this.redisclient.hset(`sessions:${userId}`
,meta.sessionId,
JSON.stringify({token, ...meta})
);
await this.redisclient.expire(`sessions:${userId}`,ttl)
}catch(err){
 console.error('Failed to persist session token:', err);
}
}


async signToken(payload: object,meta?:{device?:string, ip?:string}){
const sessionId = crypto.randomUUID();
const fullPayload = { ...payload, sessionId };
const token = jwt.sign(fullPayload,this.jwtSecret,{
expiresIn:this.expiry || "1h"
})
this.persistSessionToken(payload, token,{
sessionId,
device:meta?.device || "unknown",
ip:meta?.ip || "unknown",
createdAt: Date.now()
});

return token
};


guestToken(): string{
const payload = {
type: "guest",
id:crypto.randomUUID(),
createdAt:Date.now()
}
if(this.onGuestToken)
	this.onGuestToken();

return jwt.sign(payload,this.jwtSecret,{expiresIn:this.expiry});
}

verifyToken(token:string):JwtPayload | null{
try{
	return jwt.verify(token,this.jwtSecret)as JwtPayload;}catch{
	return null

	}
}

authenticateJWT = async(req:Request,res:Response,next:NextFunction) => {
const authHeader = req.headers.authorization;
const token = req.cookies?.token || (authHeader?.startsWith("Bearer ") ? authHeader.split(" ")[1]: null);

if(!token){
return res.status(401).json({message:"Unauthorized"})
}
try{
const decoded =jwt.verify(token,this.jwtSecret)as JwtPayload;
console.log("Redis Client exists?", !!this.redisclient);
console.log("Decoded UserID:", decoded.userId);
console.log("Full key:", `sessions:${decoded.userId}`);

if(this.redisclient && decoded.userId){
const sessions = await this.redisclient.hgetall(`sessions:${decoded.userId}`);

console.log("HGETALL called!")
const match = Object.values(sessions || {}).find(
  (s: any) => JSON.parse(s).token === token
);

if (!match) {
  return res.status(403).json({ success: false, message: "invalid session", errors: [] });
 }
}

(req as any).user =decoded;
return next();


}catch{
return res.status(403).json({success:false, message: "invalid or expired token"});
}

};
}
