import { randomUUID } from "crypto";
import type {
  AuditActor,
  AuditConfig,
  AuditEmitter,
  AuditEventInput,
  AuthAuditEvent,
  AuthAuditEventType,
} from "./types";
import { containsControlCharacter } from "../utility/safeString";

export class AuditDeliveryError extends Error {
  constructor(readonly causes: readonly unknown[]) {
    super(`Failed to deliver an audit event to ${causes.length} sink(s)`);
    this.name = "AuditDeliveryError";
  }
}

const MAX_METADATA_DEPTH = 8;
const MAX_METADATA_NODES = 2048;
const MAX_OBJECT_KEYS = 64;
const MAX_ARRAY_ITEMS = 128;
const MAX_METADATA_STRING_LENGTH = 2048;
const BLOCKED_KEYS = new Set(["__proto__", "constructor", "prototype"]);
const EVENT_TYPES = new Set<AuthAuditEventType>([
  "access_token.issued",
  "access_token.rejected",
  "refresh_token.issued",
  "refresh_token.rotated",
  "refresh_token.replay_detected",
  "refresh_token.concurrent_use_detected",
  "guest_token.issued",
  "authorization.denied",
  "session.revoked",
  "session.revoked_all",
  "session.quarantined",
  "session.quarantine_released",
  "session.risk_detected",
  "oauth.state_created",
  "oauth.state_rejected",
  "oauth.state_consumed",
  "oauth.user_created",
  "oauth.provider_linked",
  "oauth.provider_link_rejected",
  "agent_token.issued",
  "agent_token.rejected",
  "agent.revoked",
  "agent.activated",
  "security.ip_added",
  "security.ip_removed",
  "security.ip_denied",
  "security.rate_limited",
]);
const ACTOR_TYPES = new Set<AuditActor["type"]>([
  "user",
  "agent",
  "guest",
  "system",
  "unknown",
]);

const deepFreeze = <T>(value: T, seen = new WeakSet<object>()): T => {
  if (typeof value !== "object" || value === null || seen.has(value)) {
    return value;
  }
  seen.add(value);
  for (const child of Object.values(value)) {
    deepFreeze(child, seen);
  }
  return Object.freeze(value);
};

const cloneAuditValue = (
  value: unknown,
  depth: number,
  seen: WeakSet<object>,
  budget: { remaining: number },
): unknown => {
  budget.remaining -= 1;
  if (budget.remaining < 0) return "[metadata limit reached]";
  if (
    value === null ||
    typeof value === "boolean" ||
    typeof value === "number"
  ) {
    return value;
  }
  if (typeof value === "string") {
    return value.slice(0, MAX_METADATA_STRING_LENGTH);
  }
  if (typeof value === "bigint") return value.toString();
  if (typeof value !== "object") return `[${typeof value}]`;
  if (depth >= MAX_METADATA_DEPTH) return "[depth limit reached]";
  if (seen.has(value)) return "[circular]";
  seen.add(value);

  if (value instanceof Date) {
    return Number.isNaN(value.getTime()) ? "[invalid date]" : value.toISOString();
  }
  if (Array.isArray(value)) {
    return value
      .slice(0, MAX_ARRAY_ITEMS)
      .map((entry) => cloneAuditValue(entry, depth + 1, seen, budget));
  }

  const cloned: Record<string, unknown> = Object.create(null);
  let entries: [string, unknown][];
  try {
    entries = Object.entries(value).slice(0, MAX_OBJECT_KEYS);
  } catch {
    return "[unreadable metadata]";
  }
  for (const [key, child] of entries) {
    if (BLOCKED_KEYS.has(key)) continue;
    try {
      cloned[key.slice(0, 128)] = cloneAuditValue(
        child,
        depth + 1,
        seen,
        budget,
      );
    } catch {
      cloned[key.slice(0, 128)] = "[unreadable value]";
    }
  }
  return cloned;
};

const detachedMetadata = (
  metadata: Readonly<Record<string, unknown>> | undefined,
): Readonly<Record<string, unknown>> => {
  const cloned = cloneAuditValue(
    metadata ?? {},
    0,
    new WeakSet<object>(),
    { remaining: MAX_METADATA_NODES },
  ) as Record<string, unknown>;
  return deepFreeze(cloned);
};

const optionalSafeString = (
  value: unknown,
  label: string,
  maximumLength: number,
): string | undefined => {
  if (value === undefined) return undefined;
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > maximumLength ||
    containsControlCharacter(value)
  ) {
    throw new Error(
      `${label} must contain between 1 and ${maximumLength} safe characters`,
    );
  }
  return value;
};

const detachedActor = (
  actor: AuditActor,
  label: string,
): Readonly<AuditActor> => {
  if (!actor || !ACTOR_TYPES.has(actor.type)) {
    throw new Error(`${label}.type is invalid`);
  }
  const id = optionalSafeString(actor.id, `${label}.id`, 256);
  return Object.freeze({
    type: actor.type,
    ...(id ? { id } : {}),
  });
};

export class AuditDispatcher implements AuditEmitter {
  private readonly sinks;
  private readonly delivery;
  private readonly onDeliveryError;

  constructor(config: AuditConfig = {}) {
    if (config.sinks !== undefined && !Array.isArray(config.sinks)) {
      throw new Error("audit.sinks must be an array");
    }
    if ((config.sinks?.length ?? 0) > 64) {
      throw new Error("audit.sinks must not contain more than 64 sinks");
    }
    if (config.sinks?.some((sink) => typeof sink.write !== "function")) {
      throw new Error("Every audit sink must implement write(event)");
    }
    if (
      config.delivery !== undefined &&
      config.delivery !== "best-effort" &&
      config.delivery !== "strict"
    ) {
      throw new Error("audit.delivery must be best-effort or strict");
    }
    if (
      config.onDeliveryError !== undefined &&
      typeof config.onDeliveryError !== "function"
    ) {
      throw new Error("audit.onDeliveryError must be a function");
    }
    this.sinks = [...(config.sinks ?? [])];
    this.delivery = config.delivery ?? "best-effort";
    this.onDeliveryError = config.onDeliveryError;
  }

  async emit(input: AuditEventInput): Promise<void> {
    if (!input || !EVENT_TYPES.has(input.type)) {
      throw new Error("Audit event type is invalid");
    }
    if (
      input.severity !== "info" &&
      input.severity !== "warning" &&
      input.severity !== "critical"
    ) {
      throw new Error("Audit event severity is invalid");
    }
    if (
      input.outcome !== "success" &&
      input.outcome !== "denied" &&
      input.outcome !== "failure"
    ) {
      throw new Error("Audit event outcome is invalid");
    }

    const sessionId = optionalSafeString(
      input.sessionId,
      "audit.sessionId",
      256,
    );
    const tenantId = optionalSafeString(
      input.tenantId,
      "audit.tenantId",
      256,
    );
    const correlationId = optionalSafeString(
      input.correlationId,
      "audit.correlationId",
      128,
    );
    const event: AuthAuditEvent = Object.freeze({
      id: randomUUID(),
      version: 1,
      type: input.type,
      occurredAt: new Date().toISOString(),
      severity: input.severity,
      outcome: input.outcome,
      actor: detachedActor(input.actor, "audit.actor"),
      ...(input.subject
        ? { subject: detachedActor(input.subject, "audit.subject") }
        : {}),
      ...(sessionId ? { sessionId } : {}),
      ...(tenantId ? { tenantId } : {}),
      ...(correlationId ? { correlationId } : {}),
      metadata: detachedMetadata(input.metadata),
    });

    const deliveries = await Promise.allSettled(
      this.sinks.map((sink) =>
        Promise.resolve().then(() => sink.write(event)),
      ),
    );
    const failures = deliveries
      .filter(
        (result): result is PromiseRejectedResult => result.status === "rejected",
      )
      .map((result) => result.reason);

    if (!failures.length) return;

    if (this.onDeliveryError) {
      await Promise.allSettled(
        failures.map((error) =>
          Promise.resolve().then(() => this.onDeliveryError!(error, event)),
        ),
      );
    }
    if (this.delivery === "strict") {
      throw new AuditDeliveryError(failures);
    }
  }
}
