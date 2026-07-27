import type { Request } from "express";

const AUTHENIK8_AUTHENTICATED = Symbol("authenik8.authenticated");

type MarkedRequest = Request & {
  [AUTHENIK8_AUTHENTICATED]?: true;
};

export const markAuthenik8Authenticated = (request: Request): void => {
  Object.defineProperty(request, AUTHENIK8_AUTHENTICATED, {
    value: true,
    configurable: false,
    enumerable: false,
    writable: false,
  });
};

export const isAuthenik8Authenticated = (request: Request): boolean =>
  (request as MarkedRequest)[AUTHENIK8_AUTHENTICATED] === true;
