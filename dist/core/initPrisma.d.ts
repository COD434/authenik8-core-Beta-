import { PrismaClient } from "@prisma/client";
declare global {
    var prisma: PrismaClient | undefined;
}
declare const prisma: PrismaClient;
export declare const runMigration: () => Promise<void>;
declare const connectDB: () => Promise<void>;
export declare function attachPrismalogger(prisma: PrismaClient): void;
export { prisma, connectDB };
export type PrismaClientType = PrismaClient;
//# sourceMappingURL=initPrisma.d.ts.map