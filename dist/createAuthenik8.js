"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.createAuthenik8 = void 0;
const adminService_1 = require("./middleware/adminService");
const createAuthenik8 = (config) => {
    return {
        requireAdmin: (0, adminService_1.requireAdmin)(config),
    };
};
exports.createAuthenik8 = createAuthenik8;
//# sourceMappingURL=createAuthenik8.js.map