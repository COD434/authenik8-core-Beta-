export type AuditSeverity = "info" | "warning" | "critical";
export type AuditOutcome = "success" | "denied" | "failure";

export type AuthAuditEventType =
  | "access_token.issued"
  | "access_token.rejected"
  | "refresh_token.issued"
  | "refresh_token.rotated"
  | "refresh_token.replay_detected"
  | "refresh_token.concurrent_use_detected"
  | "guest_token.issued"
  | "authorization.denied"
  | "session.revoked"
  | "session.revoked_all"
  | "session.quarantined"
  | "session.quarantine_released"
  | "session.risk_detected"
  | "oauth.state_created"
  | "oauth.state_rejected"
  | "oauth.state_consumed"
  | "oauth.user_created"
  | "oauth.provider_linked"
  | "oauth.provider_link_rejected"
  | "agent_token.issued"
  | "agent_token.rejected"
  | "agent.revoked"
  | "agent.activated"
  | "security.ip_added"
  | "security.ip_removed"
  | "security.ip_denied"
  | "security.rate_limited";

export interface AuditActor {
  type: "user" | "agent" | "guest" | "system" | "unknown";
  id?: string;
}

export interface AuthAuditEvent {
  readonly id: string;
  readonly version: 1;
  readonly type: AuthAuditEventType;
  readonly occurredAt: string;
  readonly severity: AuditSeverity;
  readonly outcome: AuditOutcome;
  readonly actor: Readonly<AuditActor>;
  readonly subject?: Readonly<AuditActor>;
  readonly sessionId?: string;
  readonly tenantId?: string;
  readonly correlationId?: string;
  readonly metadata: Readonly<Record<string, unknown>>;
}

export type AuditEventInput = Omit<
  AuthAuditEvent,
  "id" | "version" | "occurredAt" | "metadata"
> & {
  metadata?: Readonly<Record<string, unknown>>;
};

export interface AuditSink {
  write(event: AuthAuditEvent): void | Promise<void>;
}

export interface AuditEmitter {
  emit(event: AuditEventInput): Promise<void>;
}

export interface AuditConfig {
  sinks?: readonly AuditSink[];
  /**
   * Best-effort delivery protects authentication availability. Strict delivery
   * makes a failed sink fail the operation that emitted the event.
   */
  delivery?: "best-effort" | "strict";
  onDeliveryError?: (
    error: unknown,
    event: AuthAuditEvent,
  ) => void | Promise<void>;
}
