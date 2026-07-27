import type { Request } from "express";
import { Address4, Address6 } from "ip-address";
import type { SessionObservation } from "../risk/types";

const MAX_DEVICE_LENGTH = 512;
const MAX_FORWARDED_HEADER_LENGTH = 4096;
const MAX_PROXY_HOPS = 32;

type ParsedIp =
  | { version: 4; canonical: string; address: Address4 }
  | { version: 6; canonical: string; address: Address6 };

type ParsedNetwork =
  | { version: 4; canonical: string; address: Address4 }
  | { version: 6; canonical: string; address: Address6 };

const parseIp = (input: unknown): ParsedIp | null => {
  if (typeof input !== "string" || input.length === 0 || input.length > 128) {
    return null;
  }
  const value = input.trim();
  if (!value || value.includes("/") || value.includes("%")) return null;

  try {
    if (value.includes(":")) {
      const address = new Address6(value);
      if (address.is4()) {
        const ipv4 = address.to4();
        return {
          version: 4,
          canonical: ipv4.correctForm(),
          address: ipv4,
        };
      }
      return {
        version: 6,
        canonical: address.correctForm(),
        address,
      };
    }
    const address = new Address4(value);
    return {
      version: 4,
      canonical: address.correctForm(),
      address,
    };
  } catch {
    return null;
  }
};

const parseNetwork = (input: unknown): ParsedNetwork | null => {
  if (typeof input !== "string" || input.length === 0 || input.length > 160) {
    return null;
  }
  const value = input.trim();
  if (!value.includes("/") || value.includes("%")) return null;

  try {
    if (value.includes(":")) {
      const address = new Address6(value);
      if (address.is4()) return null;
      const network = new Address6(
        `${address.startAddress().correctForm()}/${address.subnetMask}`,
      );
      return {
        version: 6,
        canonical: `${network.correctForm()}/${network.subnetMask}`,
        address: network,
      };
    }
    const address = new Address4(value);
    const network = new Address4(
      `${address.startAddress().correctForm()}/${address.subnetMask}`,
    );
    return {
      version: 4,
      canonical: `${network.correctForm()}/${network.subnetMask}`,
      address: network,
    };
  } catch {
    return null;
  }
};

export const normalizeIp = (input: unknown): string | null =>
  parseIp(input)?.canonical ?? null;

export const normalizeIpOrCidr = (input: unknown): string | null =>
  parseNetwork(input)?.canonical ?? normalizeIp(input);

export const isIpInCidr = (ip: string, cidr: string): boolean => {
  const parsedIp = parseIp(ip);
  const parsedNetwork = parseNetwork(cidr);
  if (!parsedIp || !parsedNetwork || parsedIp.version !== parsedNetwork.version) {
    return false;
  }
  return parsedIp.address.isInSubnet(parsedNetwork.address as never);
};

const compileTrustedNetworks = (
  trustedProxyCidrs: readonly string[],
): ParsedNetwork[] =>
  trustedProxyCidrs.map((entry) => {
    const network = parseNetwork(entry);
    if (!network) {
      throw new Error(`Invalid trusted proxy CIDR: ${entry}`);
    }
    return network;
  });

const isTrusted = (ip: ParsedIp, networks: readonly ParsedNetwork[]): boolean =>
  networks.some(
    (network) =>
      network.version === ip.version &&
      ip.address.isInSubnet(network.address as never),
  );

export const createClientIpResolver = (
  trustedProxyCidrs: readonly string[] = [],
): ((request: Request) => string) => {
  const trustedNetworks = compileTrustedNetworks(trustedProxyCidrs);

  return (request: Request): string => {
    const directPeer = parseIp(request.socket.remoteAddress);
    if (!directPeer) return "unknown";

    const forwardedHeader = request.headers["x-forwarded-for"];
    if (trustedNetworks.length === 0 || forwardedHeader === undefined) {
      return directPeer.canonical;
    }
    if (!isTrusted(directPeer, trustedNetworks)) {
      return directPeer.canonical;
    }
    if (
      typeof forwardedHeader !== "string" ||
      forwardedHeader.length > MAX_FORWARDED_HEADER_LENGTH
    ) {
      return "unknown";
    }

    const rawHops = forwardedHeader.split(",");
    if (rawHops.length === 0 || rawHops.length > MAX_PROXY_HOPS) {
      return "unknown";
    }
    const forwardedHops = rawHops.map(parseIp);
    if (forwardedHops.some((hop) => !hop)) return "unknown";

    const hops = [
      ...(forwardedHops as ParsedIp[]),
      directPeer,
    ];
    let candidate = directPeer;
    for (let index = hops.length - 2; index >= 0; index -= 1) {
      if (!isTrusted(candidate, trustedNetworks)) break;
      candidate = hops[index]!;
    }
    return candidate.canonical;
  };
};

/**
 * Resolves only from the socket unless explicit trusted proxy networks are
 * supplied. A boolean `true` is intentionally treated as no trust because it
 * cannot identify which network peers are authorized to supply the header.
 */
export const getClientIp = (
  request: Request,
  trustedProxyCidrs: boolean | readonly string[] = false,
): string =>
  createClientIpResolver(
    Array.isArray(trustedProxyCidrs) ? trustedProxyCidrs : [],
  )(request);

export const getSessionObservation = (
  request: Request,
  trustedProxyCidrs: boolean | readonly string[] = false,
): SessionObservation => ({
  ip: getClientIp(request, trustedProxyCidrs),
  device:
    request.headers["user-agent"]?.toString().slice(0, MAX_DEVICE_LENGTH) ??
    "unknown",
});

export const createSessionObservationResolver = (
  trustedProxyCidrs: readonly string[] = [],
): ((request: Request) => SessionObservation) => {
  const resolveIp = createClientIpResolver(trustedProxyCidrs);
  return (request: Request) => ({
    ip: resolveIp(request),
    device:
      request.headers["user-agent"]?.toString().slice(0, MAX_DEVICE_LENGTH) ??
      "unknown",
  });
};
