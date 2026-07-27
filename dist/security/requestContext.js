"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.createSessionObservationResolver = exports.getSessionObservation = exports.getClientIp = exports.createClientIpResolver = exports.isIpInCidr = exports.normalizeIpOrCidr = exports.normalizeIp = void 0;
const ip_address_1 = require("ip-address");
const MAX_DEVICE_LENGTH = 512;
const MAX_FORWARDED_HEADER_LENGTH = 4096;
const MAX_PROXY_HOPS = 32;
const parseIp = (input) => {
    if (typeof input !== "string" || input.length === 0 || input.length > 128) {
        return null;
    }
    const value = input.trim();
    if (!value || value.includes("/") || value.includes("%"))
        return null;
    try {
        if (value.includes(":")) {
            const address = new ip_address_1.Address6(value);
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
        const address = new ip_address_1.Address4(value);
        return {
            version: 4,
            canonical: address.correctForm(),
            address,
        };
    }
    catch {
        return null;
    }
};
const parseNetwork = (input) => {
    if (typeof input !== "string" || input.length === 0 || input.length > 160) {
        return null;
    }
    const value = input.trim();
    if (!value.includes("/") || value.includes("%"))
        return null;
    try {
        if (value.includes(":")) {
            const address = new ip_address_1.Address6(value);
            if (address.is4())
                return null;
            const network = new ip_address_1.Address6(`${address.startAddress().correctForm()}/${address.subnetMask}`);
            return {
                version: 6,
                canonical: `${network.correctForm()}/${network.subnetMask}`,
                address: network,
            };
        }
        const address = new ip_address_1.Address4(value);
        const network = new ip_address_1.Address4(`${address.startAddress().correctForm()}/${address.subnetMask}`);
        return {
            version: 4,
            canonical: `${network.correctForm()}/${network.subnetMask}`,
            address: network,
        };
    }
    catch {
        return null;
    }
};
const normalizeIp = (input) => parseIp(input)?.canonical ?? null;
exports.normalizeIp = normalizeIp;
const normalizeIpOrCidr = (input) => parseNetwork(input)?.canonical ?? (0, exports.normalizeIp)(input);
exports.normalizeIpOrCidr = normalizeIpOrCidr;
const isIpInCidr = (ip, cidr) => {
    const parsedIp = parseIp(ip);
    const parsedNetwork = parseNetwork(cidr);
    if (!parsedIp || !parsedNetwork || parsedIp.version !== parsedNetwork.version) {
        return false;
    }
    return parsedIp.address.isInSubnet(parsedNetwork.address);
};
exports.isIpInCidr = isIpInCidr;
const compileTrustedNetworks = (trustedProxyCidrs) => trustedProxyCidrs.map((entry) => {
    const network = parseNetwork(entry);
    if (!network) {
        throw new Error(`Invalid trusted proxy CIDR: ${entry}`);
    }
    return network;
});
const isTrusted = (ip, networks) => networks.some((network) => network.version === ip.version &&
    ip.address.isInSubnet(network.address));
const createClientIpResolver = (trustedProxyCidrs = []) => {
    const trustedNetworks = compileTrustedNetworks(trustedProxyCidrs);
    return (request) => {
        const directPeer = parseIp(request.socket.remoteAddress);
        if (!directPeer)
            return "unknown";
        const forwardedHeader = request.headers["x-forwarded-for"];
        if (trustedNetworks.length === 0 || forwardedHeader === undefined) {
            return directPeer.canonical;
        }
        if (!isTrusted(directPeer, trustedNetworks)) {
            return directPeer.canonical;
        }
        if (typeof forwardedHeader !== "string" ||
            forwardedHeader.length > MAX_FORWARDED_HEADER_LENGTH) {
            return "unknown";
        }
        const rawHops = forwardedHeader.split(",");
        if (rawHops.length === 0 || rawHops.length > MAX_PROXY_HOPS) {
            return "unknown";
        }
        const forwardedHops = rawHops.map(parseIp);
        if (forwardedHops.some((hop) => !hop))
            return "unknown";
        const hops = [
            ...forwardedHops,
            directPeer,
        ];
        let candidate = directPeer;
        for (let index = hops.length - 2; index >= 0; index -= 1) {
            if (!isTrusted(candidate, trustedNetworks))
                break;
            candidate = hops[index];
        }
        return candidate.canonical;
    };
};
exports.createClientIpResolver = createClientIpResolver;
/**
 * Resolves only from the socket unless explicit trusted proxy networks are
 * supplied. A boolean `true` is intentionally treated as no trust because it
 * cannot identify which network peers are authorized to supply the header.
 */
const getClientIp = (request, trustedProxyCidrs = false) => (0, exports.createClientIpResolver)(Array.isArray(trustedProxyCidrs) ? trustedProxyCidrs : [])(request);
exports.getClientIp = getClientIp;
const getSessionObservation = (request, trustedProxyCidrs = false) => ({
    ip: (0, exports.getClientIp)(request, trustedProxyCidrs),
    device: request.headers["user-agent"]?.toString().slice(0, MAX_DEVICE_LENGTH) ??
        "unknown",
});
exports.getSessionObservation = getSessionObservation;
const createSessionObservationResolver = (trustedProxyCidrs = []) => {
    const resolveIp = (0, exports.createClientIpResolver)(trustedProxyCidrs);
    return (request) => ({
        ip: resolveIp(request),
        device: request.headers["user-agent"]?.toString().slice(0, MAX_DEVICE_LENGTH) ??
            "unknown",
    });
};
exports.createSessionObservationResolver = createSessionObservationResolver;
//# sourceMappingURL=requestContext.js.map