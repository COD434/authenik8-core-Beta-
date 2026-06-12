
import {Request, Response, NextFunction} from "express";
import jwt from "jsonwebtoken";
import { RequireAdminOptions } from "../types/admin";


interface JwtPayload {
userId:string;
role: string;
}

export const requireAdmin=(options:RequireAdminOptions)=>{
	return(req:Request, res:Response,next:NextFunction)=>{

const authHeader = req.headers.authorization
const cookieToken =req.cookies?.token

let token:string | undefined;


if(authHeader && authHeader.startsWith("Bearer")){
	token=authHeader.split(" ")[1];
}

if (!token && cookieToken){
token = cookieToken
}

	if(!token){
		return res.status(401).json({error:"Unauthorized:No token provided"});}
	try{
		const decoded = jwt.verify(token,options.jwtSecret) as JwtPayload;

		if(decoded.role !== "admin"){
	        return res.status(403).json({error:"Forbidden: Admin only"})
	        }
	

	if (options.store) {
        (req as any).adminActions = {
          listSessions: async (userId: string) => {
            const sessions = await options.store.hgetall(`sessions:${userId}`);
            return Object.values(sessions || {}).map((s: any) => {

              const { token, ...meta } = JSON.parse(s);
              return meta;
            });
          },

          revokeSession: async (userId: string, sessionId: string) => {
            await options.store.hdel(`sessions:${userId}`, sessionId);
          },
          revokeAllSessions: async (userId: string) => {
            await options.store.del(`sessions:${userId}`);
          },
        };
      }
	(req as any).user = decoded;

		return next();
		}catch{
		return res.status(401).json({error:"Invalid or expired token"})
			}
		}
	}
