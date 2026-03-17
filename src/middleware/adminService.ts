
import {Request, Response, NextFunction} from "express";
import jwt from "jsonwebtoken";
import {Authenik8Config} from "../types/config";

interface JwtPayload {
id:string;
role: string;
}



export const requireAdmin=(config:Authenik8Config)=>{
return(req:Request, res:Response,next:NextFunction)=>{

const authHeader = req.headers.authorization || req.cookies.token;
const cookieToken =req.cookies?.token
const rawToken = authHeader || cookieToken

if(!rawToken){
return res.status(401).json({error:"Unauthorized:No token provided"})

}

const token= typeof rawToken === "string" && rawToken.startsWith("Bearer ") ? rawToken.split(" ")[1] : rawToken;
try{
        const decoded = jwt.verify(token,process.env.JWT_SECRET!) as JwtPayload;

        if(decoded.role !== "ADMIN"){
        res.status(403).json({error:"Forbidden: Admin only"})
        }

next();
}catch(error){
res.status(401).json({error:"Invalid or expired token"})
}
}
}
