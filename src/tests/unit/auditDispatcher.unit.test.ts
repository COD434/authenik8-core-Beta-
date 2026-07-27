import { describe, expect, it, vi } from "vitest";
import {
  AuditDeliveryError,
  AuditDispatcher,
} from "../../audit/auditDispatcher";

const event = {
  type: "session.revoked" as const,
  severity: "warning" as const,
  outcome: "success" as const,
  actor: { type: "system" as const },
};

describe("AuditDispatcher", () => {
  it("rejects runtime configuration that could silently change delivery semantics", () => {
    expect(
      () => new AuditDispatcher({ delivery: "STRICT" as never }),
    ).toThrow(/delivery/i);
    expect(
      () => new AuditDispatcher({ sinks: "sink" as never }),
    ).toThrow(/sinks/i);
  });

  it("delivers one immutable envelope shape to every sink", async () => {
    const first = { write: vi.fn() };
    const second = { write: vi.fn() };
    const audit = new AuditDispatcher({ sinks: [first, second] });

    await audit.emit(event);

    expect(first.write).toHaveBeenCalledOnce();
    expect(second.write).toHaveBeenCalledWith(first.write.mock.calls[0]![0]);
    expect(first.write.mock.calls[0]![0]).toMatchObject({
      ...event,
      id: expect.any(String),
      version: 1,
      occurredAt: expect.any(String),
      metadata: {},
    });
    expect(Object.isFrozen(first.write.mock.calls[0]![0])).toBe(true);
    expect(Object.isFrozen(first.write.mock.calls[0]![0].metadata)).toBe(true);
  });

  it("keeps best-effort delivery available while reporting sink errors", async () => {
    const failure = new Error("sink unavailable");
    const onDeliveryError = vi.fn();
    const audit = new AuditDispatcher({
      sinks: [{ write: vi.fn().mockRejectedValue(failure) }],
      onDeliveryError,
    });

    await expect(audit.emit(event)).resolves.toBeUndefined();
    expect(onDeliveryError).toHaveBeenCalledWith(
      failure,
      expect.objectContaining({ type: "session.revoked" }),
    );
  });

  it("detaches and deeply freezes nested metadata before invoking a sink", async () => {
    const required = ["records:read"];
    const sink = {
      write: vi.fn((delivered) => {
        const nested = delivered.metadata.required as string[];
        expect(Object.isFrozen(nested)).toBe(true);
        expect(() => nested.push("records:write")).toThrow();
      }),
    };
    const audit = new AuditDispatcher({ sinks: [sink] });

    await audit.emit({
      ...event,
      metadata: { required },
    });
    required.push("caller-only-change");

    const delivered = sink.write.mock.calls[0]![0];
    expect(delivered.metadata.required).toEqual(["records:read"]);
  });

  it("contains synchronous sink exceptions in best-effort mode", async () => {
    const second = { write: vi.fn() };
    const audit = new AuditDispatcher({
      sinks: [
        {
          write() {
            throw new Error("synchronous sink failure");
          },
        },
        second,
      ],
    });

    await expect(audit.emit(event)).resolves.toBeUndefined();
    expect(second.write).toHaveBeenCalledOnce();
  });

  it("can fail security operations when strict delivery is configured", async () => {
    const audit = new AuditDispatcher({
      delivery: "strict",
      sinks: [{ write: vi.fn().mockRejectedValue(new Error("sink unavailable")) }],
    });

    await expect(audit.emit(event)).rejects.toBeInstanceOf(AuditDeliveryError);
  });

  it("rejects malformed envelope fields before they reach a sink", async () => {
    const sink = { write: vi.fn() };
    const audit = new AuditDispatcher({ sinks: [sink] });

    await expect(
      audit.emit({
        ...event,
        actor: { type: "user", id: "user\nforged" },
      }),
    ).rejects.toThrow(/actor.id/i);
    await expect(
      audit.emit({
        ...event,
        correlationId: "x".repeat(129),
      }),
    ).rejects.toThrow(/correlationId/i);
    expect(sink.write).not.toHaveBeenCalled();
  });
});
