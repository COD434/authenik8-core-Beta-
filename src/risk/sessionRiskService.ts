import { createHash } from "crypto";
import type { AuditEmitter } from "../audit/types";
import type {
  ContextChangeAction,
  RiskPrincipal,
  RiskSignal,
  RiskSignalType,
  SessionObservation,
  SessionRiskConfig,
  SessionRiskReporter,
  SessionRiskState,
  SessionRiskStore,
} from "./types";
import { validateRedisKeyPrefix } from "../redis/keyNamespace";
import { containsControlCharacter } from "../utility/safeString";

const DEFAULT_SIGNAL_WINDOW_SECONDS = 5 * 60;
const DEFAULT_QUARANTINE_SECONDS = 15 * 60;
const DEFAULT_CONCURRENT_REFRESH_THRESHOLD = 2;
const DEFAULT_SUSPICIOUS_AGENT_THRESHOLD = 5;
const MAX_RISK_IDENTIFIER_LENGTH = 256;
const MAX_RISK_FINGERPRINT_LENGTH = 512;
const MAX_RISK_STATE_BYTES = 4096;
const SIGNAL_TYPES: readonly RiskSignalType[] = [
  "refresh_replay",
  "concurrent_refresh",
  "ip_change",
  "device_change",
  "suspicious_agent_activity",
];
const SIGNAL_TYPE_SET = new Set<RiskSignalType>(SIGNAL_TYPES);
const CONTEXT_ACTIONS = new Set<ContextChangeAction>([
  "ignore",
  "audit",
  "quarantine",
]);

const activeState = (): SessionRiskState => ({
  status: "active",
  reasons: [],
});

const positiveInteger = (
  value: number | undefined,
  fallback: number,
  name: string,
  maximum = 366 * 24 * 60 * 60,
): number => {
  const resolved = value ?? fallback;
  if (
    !Number.isSafeInteger(resolved) ||
    resolved <= 0 ||
    resolved > maximum
  ) {
    throw new Error(`${name} must be between 1 and ${maximum}`);
  }
  return resolved;
};

const validatePrincipal = (principal: RiskPrincipal): void => {
  if (
    !principal ||
    (principal.kind !== "human" && principal.kind !== "agent") ||
    typeof principal.id !== "string" ||
    principal.id.length === 0 ||
    principal.id.length > MAX_RISK_IDENTIFIER_LENGTH ||
    containsControlCharacter(principal.id) ||
    typeof principal.sessionId !== "string" ||
    principal.sessionId.length === 0 ||
    principal.sessionId.length > MAX_RISK_IDENTIFIER_LENGTH ||
    containsControlCharacter(principal.sessionId)
  ) {
    throw new Error("Risk principal is invalid");
  }
};

const validateSignalType = (value: unknown): RiskSignalType => {
  if (!SIGNAL_TYPE_SET.has(value as RiskSignalType)) {
    throw new Error("Risk signal type is invalid");
  }
  return value as RiskSignalType;
};

const parseRiskState = (stored: string): SessionRiskState => {
  if (
    stored.length > MAX_RISK_STATE_BYTES ||
    Buffer.byteLength(stored, "utf8") > MAX_RISK_STATE_BYTES
  ) {
    throw new Error("Stored risk state exceeds the size limit");
  }

  let value: unknown;
  try {
    value = JSON.parse(stored);
  } catch {
    throw new Error("Stored risk state is invalid");
  }
  if (!value || typeof value !== "object") {
    throw new Error("Stored risk state is invalid");
  }

  const candidate = value as Partial<SessionRiskState>;
  if (
    candidate.status !== "quarantined" ||
    !Array.isArray(candidate.reasons) ||
    candidate.reasons.length === 0 ||
    candidate.reasons.length > SIGNAL_TYPES.length ||
    candidate.reasons.some((reason) => !SIGNAL_TYPE_SET.has(reason)) ||
    new Set(candidate.reasons).size !== candidate.reasons.length ||
    typeof candidate.quarantinedAt !== "string" ||
    !Number.isFinite(Date.parse(candidate.quarantinedAt)) ||
    typeof candidate.expiresAt !== "string" ||
    !Number.isFinite(Date.parse(candidate.expiresAt))
  ) {
    throw new Error("Stored risk state is invalid");
  }

  return {
    status: "quarantined",
    reasons: [...candidate.reasons],
    quarantinedAt: candidate.quarantinedAt,
    expiresAt: candidate.expiresAt,
  };
};

export class SessionRiskService implements SessionRiskReporter {
  private readonly enabled;
  private readonly signalWindowSeconds;
  private readonly quarantineSeconds;
  private readonly concurrentRefreshThreshold;
  private readonly suspiciousAgentThreshold;
  private readonly ipChangeAction;
  private readonly deviceChangeAction;
  private readonly keyPrefix: string;

  constructor(
    private readonly store: SessionRiskStore,
    config: SessionRiskConfig = {},
    private readonly audit?: AuditEmitter,
    keyPrefix = "authenik8:risk",
  ) {
    this.keyPrefix = validateRedisKeyPrefix(keyPrefix);
    if (
      config.enabled !== undefined &&
      typeof config.enabled !== "boolean"
    ) {
      throw new Error("risk.enabled must be a boolean");
    }
    this.enabled = config.enabled ?? true;
    this.signalWindowSeconds = positiveInteger(
      config.signalWindowSeconds,
      DEFAULT_SIGNAL_WINDOW_SECONDS,
      "risk.signalWindowSeconds",
    );
    this.quarantineSeconds = positiveInteger(
      config.quarantineSeconds,
      DEFAULT_QUARANTINE_SECONDS,
      "risk.quarantineSeconds",
    );
    this.concurrentRefreshThreshold = positiveInteger(
      config.concurrentRefreshThreshold,
      DEFAULT_CONCURRENT_REFRESH_THRESHOLD,
      "risk.concurrentRefreshThreshold",
      1_000_000,
    );
    this.suspiciousAgentThreshold = positiveInteger(
      config.suspiciousAgentThreshold,
      DEFAULT_SUSPICIOUS_AGENT_THRESHOLD,
      "risk.suspiciousAgentThreshold",
      1_000_000,
    );
    this.ipChangeAction = config.ipChangeAction ?? "audit";
    this.deviceChangeAction = config.deviceChangeAction ?? "audit";
    if (
      !CONTEXT_ACTIONS.has(this.ipChangeAction) ||
      !CONTEXT_ACTIONS.has(this.deviceChangeAction)
    ) {
      throw new Error(
        "Risk context actions must be ignore, audit, or quarantine",
      );
    }
  }

  async report(signal: RiskSignal): Promise<SessionRiskState> {
    validatePrincipal(signal.principal);
    validateSignalType(signal.type);
    if (
      signal.fingerprint !== undefined &&
      (typeof signal.fingerprint !== "string" ||
        signal.fingerprint.length === 0 ||
        signal.fingerprint.length > MAX_RISK_FINGERPRINT_LENGTH ||
        containsControlCharacter(signal.fingerprint))
    ) {
      throw new Error("Risk signal fingerprint is invalid");
    }
    if (!this.enabled || this.actionFor(signal.type) === "ignore") {
      return this.getState(signal.principal);
    }

    if (
      signal.fingerprint &&
      !(await this.claimFingerprint(signal.principal, signal))
    ) {
      return this.getState(signal.principal);
    }

    const count = await this.incrementSignal(signal.principal, signal.type);
    const quarantined =
      count >= this.thresholdFor(signal.type)
        ? await this.quarantine(signal.principal, [signal.type])
        : undefined;
    await this.audit?.emit({
      type: "session.risk_detected",
      severity: signal.type === "refresh_replay" ? "critical" : "warning",
      outcome: "denied",
      actor: {
        type: signal.principal.kind === "agent" ? "agent" : "user",
        id: signal.principal.id,
      },
      sessionId: signal.principal.sessionId,
      metadata: {
        signal: signal.type,
        count,
        ...signal.metadata,
      },
    });

    return quarantined ?? this.getState(signal.principal);
  }

  async assessContext(
    principal: RiskPrincipal,
    expected: SessionObservation,
    observed: SessionObservation,
  ): Promise<SessionRiskState> {
    validatePrincipal(principal);
    let state = await this.getState(principal);
    const changes: Array<{
      type: "ip_change" | "device_change";
      before?: string;
      after?: string;
    }> = [
      { type: "ip_change", before: expected.ip, after: observed.ip },
      {
        type: "device_change",
        before: expected.device,
        after: observed.device,
      },
    ];

    for (const change of changes) {
      if (
        !this.isKnown(change.before) ||
        !this.isKnown(change.after) ||
        change.before === change.after
      ) {
        continue;
      }

      state = await this.report({
        type: change.type,
        principal,
        fingerprint: this.fingerprint(change.before!, change.after!),
        metadata: { changed: change.type === "ip_change" ? "ip" : "device" },
      });
      if (state.status === "quarantined") return state;
    }

    return state;
  }

  async getState(principal: RiskPrincipal): Promise<SessionRiskState> {
    validatePrincipal(principal);
    if (!this.enabled) return activeState();
    const stored = await this.store.get(this.quarantineKey(principal));
    if (!stored) return activeState();
    return parseRiskState(stored);
  }

  async isQuarantined(principal: RiskPrincipal): Promise<boolean> {
    return (await this.getState(principal)).status === "quarantined";
  }

  async quarantine(
    principal: RiskPrincipal,
    reasons: readonly RiskSignalType[],
  ): Promise<SessionRiskState> {
    validatePrincipal(principal);
    const validatedReasons = [...new Set(reasons.map(validateSignalType))];
    if (validatedReasons.length === 0) {
      throw new Error("Quarantine requires at least one valid reason");
    }
    const existing = await this.getState(principal);
    const now = new Date();
    const state: SessionRiskState = {
      status: "quarantined",
      reasons: [...new Set([...existing.reasons, ...validatedReasons])],
      quarantinedAt: existing.quarantinedAt ?? now.toISOString(),
      expiresAt: new Date(
        now.getTime() + this.quarantineSeconds * 1000,
      ).toISOString(),
    };
    await this.store.set(
      this.quarantineKey(principal),
      JSON.stringify(state),
      this.quarantineSeconds,
    );
    await this.audit?.emit({
      type: "session.quarantined",
      severity: "critical",
      outcome: "denied",
      actor: { type: "system" },
      subject: {
        type: principal.kind === "agent" ? "agent" : "user",
        id: principal.id,
      },
      sessionId: principal.sessionId,
      metadata: { reasons: state.reasons },
    });
    return state;
  }

  async release(principal: RiskPrincipal): Promise<void> {
    validatePrincipal(principal);
    await this.store.delete([
      this.quarantineKey(principal),
      ...SIGNAL_TYPES.map((type) => this.counterKey(principal, type)),
    ]);
    await this.audit?.emit({
      type: "session.quarantine_released",
      severity: "info",
      outcome: "success",
      actor: { type: "system" },
      subject: {
        type: principal.kind === "agent" ? "agent" : "user",
        id: principal.id,
      },
      sessionId: principal.sessionId,
    });
  }

  private actionFor(type: RiskSignalType): ContextChangeAction {
    if (type === "ip_change") return this.ipChangeAction;
    if (type === "device_change") return this.deviceChangeAction;
    return "quarantine";
  }

  private thresholdFor(type: RiskSignalType): number {
    if (type === "refresh_replay") return 1;
    if (type === "concurrent_refresh") {
      return this.concurrentRefreshThreshold;
    }
    if (type === "suspicious_agent_activity") {
      return this.suspiciousAgentThreshold;
    }
    return this.actionFor(type) === "quarantine"
      ? 1
      : Number.POSITIVE_INFINITY;
  }

  private async incrementSignal(
    principal: RiskPrincipal,
    type: RiskSignalType,
  ): Promise<number> {
    const key = this.counterKey(principal, type);
    const count = await this.store.increment(key);
    if (!Number.isSafeInteger(count) || count < 1) {
      throw new Error("Risk signal counter returned an invalid value");
    }
    if (count === 1) {
      await this.store.expire(key, this.signalWindowSeconds);
    }
    return count;
  }

  private async claimFingerprint(
    principal: RiskPrincipal,
    signal: RiskSignal,
  ): Promise<boolean> {
    const fingerprint = createHash("sha256")
      .update(signal.fingerprint!)
      .digest("base64url");
    const key = `${this.principalKey(principal)}:seen:${signal.type}:${fingerprint}`;
    return this.store.setIfAbsent(
      key,
      "1",
      this.signalWindowSeconds,
    );
  }

  private isKnown(value?: string): boolean {
    return !!value && value !== "unknown";
  }

  private fingerprint(before: string, after: string): string {
    return createHash("sha256")
      .update(before)
      .update("\0")
      .update(after)
      .digest("base64url");
  }

  private principalKey(principal: RiskPrincipal): string {
    const identity = createHash("sha256")
      .update(principal.kind)
      .update("\0")
      .update(principal.id)
      .update("\0")
      .update(principal.sessionId)
      .digest("base64url");
    return [
      this.keyPrefix,
      principal.kind,
      identity,
    ].join(":");
  }

  private quarantineKey(principal: RiskPrincipal): string {
    return `${this.principalKey(principal)}:quarantine`;
  }

  private counterKey(
    principal: RiskPrincipal,
    type: RiskSignalType,
  ): string {
    return `${this.principalKey(principal)}:count:${type}`;
  }
}
