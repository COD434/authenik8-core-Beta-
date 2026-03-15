//import dotenv from "dotenv";
import {Request, Response, NextFunction} from "express";
import jwt from "jsonwebtoken";
import { SignOptions } from "jsonwebtoken"
//import {setupRedis} from "./redis";
//import {guestCounter, guestBlocked} from "./Monitor/monitor";
import crypto from "crypto"
//dotenv.config();

interface JwtPayload {
userId: string;
email: string;
type?:string;
id?:string;
createdAt?:number;
}

export interface JWTOptions{
secret:string;
expiry?:SignOptions["expiresIn"];
redisClient?:any;
onGuestToken?: () => void;
}
export class JWTService{

private secret:string;
private expiry?:SignOptions["expiresIn"]

//constructor(secret: string, expiry:SignOptions["expiresIn"]){
//this.secret = secret
//this.expiry = expiry
//}

signToken(payload: object){
return jwt.sign(payload,this.secret,{
expiresIn:this.expiry})
};


private redisclient?:any;
private onGuestToken?: () => void;


constructor(options:JWTOptions){
this.secret = options.secret;
this.expiry = options.expiry;
this.redisclient = options.redisClient;
this.onGuestToken = options.onGuestToken;

}


guestToken(): string{
const payload = {
type: "guest",
id:crypto.randomUUID(),
createdAt:Date.now
}
if(this.onGuestToken)
	this.onGuestToken();

return jwt.sign(payload,this.secret,{expiresIn:this.expiry});
}

verifyToken(token:string):JwtPayload | null{
try{
	return jwt.verify(token,this.secret)as JwtPayload;}catch{
	return null
	}
}

authenticateJWT = async(
	req:Request,
	res:Response,
	next:NextFunction
) => {
const authHeader = req.headers.authorization;
const token = req.cookies?.token || (authHeader?.startsWith("Bearer") ? authHeader.split(" ")[1]:null);

if(!token){
return res.status(401).json({message:"Unauthorized"})
}
try{
const decoded =jwt.verify(token,this.secret)as JwtPayload;

if(this.redisclient && decoded.userId){
const storedToken = await this.redisclient.get(`session:${decoded.userId}`);

if(storedToken !== token){
return res
.status(403)
.json({success:false,message:"invalid session",errors: []})
}
}
(req as any).user =decoded;
next();

}catch{
return res.status(403)
.json({success:false, message: "invalid or expired token"});
}
}
}
		
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

