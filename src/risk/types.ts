export type RiskPrincipalKind = "human" | "agent";
export type RiskSignalType =
  | "refresh_replay"
  | "concurrent_refresh"
  | "ip_change"
  | "device_change"
  | "suspicious_agent_activity";

export interface RiskPrincipal {
  kind: RiskPrincipalKind;
  id: string;
  sessionId: string;
}

export interface SessionObservation {
  ip?: string;
  device?: string;
}

export interface RiskSignal {
  type: RiskSignalType;
  principal: RiskPrincipal;
  fingerprint?: string;
  metadata?: Readonly<Record<string, unknown>>;
}

export interface SessionRiskState {
  status: "active" | "quarantined";
  reasons: RiskSignalType[];
  quarantinedAt?: string;
  expiresAt?: string;
}

export type ContextChangeAction = "ignore" | "audit" | "quarantine";

export interface SessionRiskConfig {
  enabled?: boolean;
  signalWindowSeconds?: number;
  quarantineSeconds?: number;
  concurrentRefreshThreshold?: number;
  suspiciousAgentThreshold?: number;
  ipChangeAction?: ContextChangeAction;
  deviceChangeAction?: ContextChangeAction;
}

export interface SessionRiskReporter {
  report(signal: RiskSignal): Promise<SessionRiskState>;
  assessContext(
    principal: RiskPrincipal,
    expected: SessionObservation,
    observed: SessionObservation,
  ): Promise<SessionRiskState>;
  getState(principal: RiskPrincipal): Promise<SessionRiskState>;
  isQuarantined(principal: RiskPrincipal): Promise<boolean>;
  quarantine(
    principal: RiskPrincipal,
    reasons: readonly RiskSignalType[],
  ): Promise<SessionRiskState>;
  release(principal: RiskPrincipal): Promise<void>;
}

export interface SessionRiskStore {
  get(key: string): Promise<string | null>;
  set(key: string, value: string, ttlSeconds: number): Promise<void>;
  setIfAbsent(
    key: string,
    value: string,
    ttlSeconds: number,
  ): Promise<boolean>;
  increment(key: string): Promise<number>;
  expire(key: string, ttlSeconds: number): Promise<void>;
  delete(keys: readonly string[]): Promise<void>;
}
