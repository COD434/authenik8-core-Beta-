import jwt from "jsonwebtoken";

export class MissingTokenError extends Error{
constructor(message="Missing Token")
{
super(message);
this.name ="MissingTokenError";
}
}

export class InvalidTokenError extends
Error{
constructor(message = "Invalid refresh token"){
super(message);
this.name = "InvalidTokenError";
}
}


interface TokenPayload{
userId: string;
email: string;
}


export interface TokenStore{
get(key:string):Promise<string| null>;
set?(key: string, value: string, expiry?:number):Promise<void>;
del?(key :string):Promise<void>;

}
export interface RefreshServiceOptions {
	redisClient:TokenStore;
	accessTokenSecret:string;
	refreshTokenSecret:string;
	accessTokenExpiry:string;
	rotateRefreshTokens?:boolean;
	refreshTokenExpiry?:string;
}

export interface RefreshResult{
accessToken:string;
refreshToken?:string;
}


export class RefreshService{
private redisClient:TokenStore;
private accessTokenSecret:string;
private refreshTokenSecret:string;
private accessTokenExpiry:string;
private rotateRefreshTokens:boolean;
private refreshTokenExpiry:string;


constructor(options:RefreshServiceOptions){
this.redisClient = options.redisClient;
this.accessTokenSecret = options.accessTokenSecret;
this.refreshTokenSecret =options.refreshTokenSecret;
this.accessTokenExpiry = options.accessTokenExpiry ?? "15m";
this.rotateRefreshTokens = options.rotateRefreshTokens ?? false;
this.refreshTokenExpiry = options.refreshTokenExpiry ?? "7d"
 }

 async refresh(refreshToken?:string):Promise<RefreshResult>{
	 if(!refreshToken){
	 throw new MissingTokenError()
	 }
 
let decoded:TokenPayload;
try {
decoded = jwt.verify(refreshToken,this.refreshTokenSecret) as TokenPayload;
}catch(err){
throw new InvalidTokenError()
}

const storedToken= await this.redisClient.get(`refresh:${decoded.userId}`)

if (storedToken !== refreshToken){
throw new InvalidTokenError();
}
let newRefreshToken:string | undefined;

if(this.rotateRefreshTokens && this.redisClient.set && this.redisClient.del){
await this.redisClient.del(`refresh:${decoded.userId}`);

 newRefreshToken =jwt.sign({userId:decoded.userId,email : decoded.email},
	this.refreshTokenSecret,
{expiresIn:this.refreshTokenExpiry as jwt.SignOptions["expiresIn"]});

await this.redisClient.set(`refresh:${decoded.userId}`,newRefreshToken)
}

const newAccessToken = jwt.sign(
	{

	userId: decoded.userId,
	email: decoded.email
	},
this.accessTokenSecret,
{expiresIn: this.accessTokenExpiry as jwt.SignOptions["expiresIn"]});
 return{
 accessToken:newAccessToken,
 refreshToken:newRefreshToken,
 };
}
}

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
