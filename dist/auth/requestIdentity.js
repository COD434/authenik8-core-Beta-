"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.isAuthenik8Authenticated = exports.markAuthenik8Authenticated = void 0;
const AUTHENIK8_AUTHENTICATED = Symbol("authenik8.authenticated");
const markAuthenik8Authenticated = (request) => {
    Object.defineProperty(request, AUTHENIK8_AUTHENTICATED, {
        value: true,
        configurable: false,
        enumerable: false,
        writable: false,
    });
};
exports.markAuthenik8Authenticated = markAuthenik8Authenticated;
const isAuthenik8Authenticated = (request) => request[AUTHENIK8_AUTHENTICATED] === true;
exports.isAuthenik8Authenticated = isAuthenik8Authenticated;
//# sourceMappingURL=requestIdentity.js.map