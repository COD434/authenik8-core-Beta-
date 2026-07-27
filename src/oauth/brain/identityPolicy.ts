export interface IdentityPolicy {
  readonly autoLinkOnVerifiedEmailMatch: boolean;
  readonly allowUnverifiedAutoLink: boolean;
}

export type IdentityPolicyConfig = Partial<IdentityPolicy>;

export const identityPolicy: IdentityPolicy = Object.freeze({
  autoLinkOnVerifiedEmailMatch: false,
  allowUnverifiedAutoLink: false,
});

export const resolveIdentityPolicy = (
  configured: IdentityPolicyConfig = {},
): IdentityPolicy => {
  if (
    (configured.autoLinkOnVerifiedEmailMatch !== undefined &&
      typeof configured.autoLinkOnVerifiedEmailMatch !== "boolean") ||
    (configured.allowUnverifiedAutoLink !== undefined &&
      typeof configured.allowUnverifiedAutoLink !== "boolean")
  ) {
    throw new Error("OAuth identity policy flags must be boolean values");
  }
  return Object.freeze({
    autoLinkOnVerifiedEmailMatch:
      configured.autoLinkOnVerifiedEmailMatch ?? false,
    allowUnverifiedAutoLink: configured.allowUnverifiedAutoLink ?? false,
  });
};
