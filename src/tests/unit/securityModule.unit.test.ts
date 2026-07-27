import type { Request } from "express";
import { describe, expect, it } from "vitest";
import {
  createClientIpResolver,
  getClientIp,
  normalizeIpOrCidr,
} from "../../security/requestContext";

const request = (remoteAddress: string, forwarded?: string) =>
  ({
    socket: { remoteAddress },
    headers: forwarded ? { "x-forwarded-for": forwarded } : {},
    // A preprocessed Express value must never override the actual socket.
    ip: "203.0.113.250",
  }) as unknown as Request;

describe("request network context", () => {
  it("uses the socket peer and never Express req.ip by default", () => {
    expect(getClientIp(request("198.51.100.20", "203.0.113.10"))).toBe(
      "198.51.100.20",
    );
  });

  it("normalizes IPv4-mapped IPv6 and network addresses", () => {
    expect(getClientIp(request("::ffff:192.0.2.10"))).toBe("192.0.2.10");
    expect(normalizeIpOrCidr("10.20.30.40/8")).toBe("10.0.0.0/8");
  });

  it("returns unknown for malformed or oversized trusted forwarding chains", () => {
    const resolve = createClientIpResolver(["10.0.0.0/8"]);
    expect(resolve(request("10.0.0.1", "malformed"))).toBe("unknown");
    expect(
      resolve(
        request(
          "10.0.0.1",
          Array.from({ length: 33 }, () => "10.0.0.2").join(","),
        ),
      ),
    ).toBe("unknown");
    expect(
      resolve({
        socket: { remoteAddress: "10.0.0.1" },
        headers: { "x-forwarded-for": ["203.0.113.1", "10.0.0.2"] },
      } as unknown as Request),
    ).toBe("unknown");
  });

  it("validates every configured trusted proxy network", () => {
    expect(() => createClientIpResolver(["not-a-cidr"])).toThrow(
      /invalid trusted proxy CIDR/i,
    );
  });
});
