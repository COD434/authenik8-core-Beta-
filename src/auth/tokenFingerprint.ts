import { createHash, timingSafeEqual } from "crypto";

export const tokenFingerprint = (token: string): string =>
  createHash("sha256").update(token).digest("base64url");

export const tokenFingerprintMatches = (
  expectedFingerprint: string,
  token: string,
): boolean => {
  const expected = Buffer.from(expectedFingerprint);
  const actual = Buffer.from(tokenFingerprint(token));
  return (
    expected.length === actual.length && timingSafeEqual(expected, actual)
  );
};
