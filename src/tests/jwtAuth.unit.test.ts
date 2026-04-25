import { JWTService } from "../auth/jwtAuth";

describe("JWTService", () => {
  const jwtSecret = "unit-test-secret";

  test("signToken produces a token that verifyToken accepts", () => {
    const service = new JWTService({
      jwtSecret,
      expiry: "15m"
    });

    const token = service.signToken({
      userId: "user-1",
      email: "user@test.com"
    });

    expect(typeof token).toBe("string");
    expect(
      service.verifyToken(token)
    ).toMatchObject({
      userId: "user-1",
      email: "user@test.com"
    });
  });

  test("verifyToken returns null for an invalid token", () => {
    const service = new JWTService({
      jwtSecret
    });

    expect(service.verifyToken("not-a-jwt")).toBeNull();
  });

  test("guestToken emits a guest payload", () => {
    let hookCalls = 0;
    const service = new JWTService({
      jwtSecret,
      expiry: "10m",
      onGuestToken: () => {
        hookCalls += 1;
      }
    });

    const token = service.guestToken();
    const payload = service.verifyToken(token);

    expect(hookCalls).toBe(1);
    expect(payload).toMatchObject({
      type: "guest"
    });
    expect(typeof payload?.id).toBe("string");
    expect(typeof payload?.createdAt).toBe("number");
  });
});
