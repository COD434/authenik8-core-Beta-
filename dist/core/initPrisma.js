"use strict";
var _a;
Object.defineProperty(exports, "__esModule", { value: true });
exports.connectDB = exports.prisma = exports.runMigration = void 0;
exports.attachPrismalogger = attachPrismalogger;
const child_process_1 = require("child_process");
const client_1 = require("@prisma/client");
const prisma = (_a = globalThis.prisma) !== null && _a !== void 0 ? _a : new client_1.PrismaClient({
    log: [
        { level: "warn", emit: "event" },
        { level: "info", emit: "event" },
        { level: "error", emit: "event" },
    ]
});
exports.prisma = prisma;
if (process.env.NODE_ENV !== "production") {
    globalThis.prisma = prisma;
}
const runMigration = async () => {
    try {
        const migrationStatus = (0, child_process_1.execSync)('npx prisma migrate status').toString();
        if (!migrationStatus.includes('Database schema is up to date')) {
            console.log('Running database migrations...');
            (0, child_process_1.execSync)('npx prisma migrate deploy', { stdio: 'inherit' });
        }
    }
    catch (err) {
        console.error('migration  failed:', err);
        throw err;
    }
};
exports.runMigration = runMigration;
const connectDB = async () => {
    try {
        await prisma.$connect();
        console.log("Database connected successfully");
    }
    catch (err) {
        console.error("Database connection error:", err);
        process.exit(1);
    }
};
exports.connectDB = connectDB;
process.on("SIGINT", async () => {
    await prisma.$disconnect();
    process.exit(0);
});
process.on("SIGTERM", async () => {
    await prisma.$disconnect();
    process.exit(0);
});
function attachPrismalogger(prisma) {
    prisma.$on("warn", (e) => {
        console.warn('Prisma warn', e);
    });
    prisma.$on("info", (e) => {
        console.info("Prisma info", e);
    });
    prisma.$on("error", (e) => {
        console.error("Prisma error", e);
    });
}
//# sourceMappingURL=initPrisma.js.map