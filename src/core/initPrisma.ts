import {execSync} from "child_process";
import { PrismaClient,Prisma } from "@prisma/client";


declare global {
  var prisma: PrismaClient | undefined;
}

 const prisma: PrismaClient= globalThis.prisma ?? new PrismaClient({
log:[
	{level:"warn", emit:"event"},
	{level:"info", emit:"event"},
	{level:"error", emit:"event"},
]
});
 if(process.env.NODE_ENV !== "production"){
 globalThis.prisma = prisma;
 }

export const runMigration = async () =>{
try{
const migrationStatus = execSync('npx prisma migrate status').toString();

if (!migrationStatus.includes('Database schema is up to date')){
console.log('Running database migrations...');
execSync('npx prisma migrate deploy',{stdio:'inherit'})
   }
  }catch(err){
console.error('migration  failed:',err)
throw err;
 }
};


const connectDB = async ()=> {
try{
await prisma.$connect();
console.log("Database connected successfully");
}catch(err) {
console.error("Database connection error:",err);
process.exit(1);
 }
};

process.on("SIGINT", async () => {
await prisma.$disconnect();
process.exit(0);
});
process.on("SIGTERM",async () =>{
await prisma.$disconnect();
process.exit(0);
})
export function attachPrismalogger(prisma:PrismaClient){

(prisma.$on as any)("warn", (e:Prisma.LogEvent) =>{
console.warn('Prisma warn',e)
});

(prisma.$on as any)("info",(e:Prisma.LogEvent)=>{
console.info("Prisma info",e)
});


(prisma.$on as any)("error", (e:Prisma.LogEvent)=>{
console.error("Prisma error",e)
});
}

export {prisma, connectDB}
export type PrismaClientType = PrismaClient
