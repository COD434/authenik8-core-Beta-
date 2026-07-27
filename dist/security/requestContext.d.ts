import type { Request } from "express";
import type { SessionObservation } from "../risk/types";
export declare const normalizeIp: (input: unknown) => string | null;
export declare const normalizeIpOrCidr: (input: unknown) => string | null;
export declare const isIpInCidr: (ip: string, cidr: string) => boolean;
export declare const createClientIpResolver: (trustedProxyCidrs?: readonly string[]) => ((request: Request) => string);
/**
 * Resolves only from the socket unless explicit trusted proxy networks are
 * supplied. A boolean `true` is intentionally treated as no trust because it
 * cannot identify which network peers are authorized to supply the header.
 */
export declare const getClientIp: (request: Request, trustedProxyCidrs?: boolean | readonly string[]) => string;
export declare const getSessionObservation: (request: Request, trustedProxyCidrs?: boolean | readonly string[]) => SessionObservation;
export declare const createSessionObservationResolver: (trustedProxyCidrs?: readonly string[]) => ((request: Request) => SessionObservation);
//# sourceMappingURL=requestContext.d.ts.map