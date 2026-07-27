import type { AuditEmitter } from "../audit/types";
import type { RiskPrincipal, RiskSignal, RiskSignalType, SessionObservation, SessionRiskConfig, SessionRiskReporter, SessionRiskState, SessionRiskStore } from "./types";
export declare class SessionRiskService implements SessionRiskReporter {
    private readonly store;
    private readonly audit?;
    private readonly enabled;
    private readonly signalWindowSeconds;
    private readonly quarantineSeconds;
    private readonly concurrentRefreshThreshold;
    private readonly suspiciousAgentThreshold;
    private readonly ipChangeAction;
    private readonly deviceChangeAction;
    private readonly keyPrefix;
    constructor(store: SessionRiskStore, config?: SessionRiskConfig, audit?: AuditEmitter | undefined, keyPrefix?: string);
    report(signal: RiskSignal): Promise<SessionRiskState>;
    assessContext(principal: RiskPrincipal, expected: SessionObservation, observed: SessionObservation): Promise<SessionRiskState>;
    getState(principal: RiskPrincipal): Promise<SessionRiskState>;
    isQuarantined(principal: RiskPrincipal): Promise<boolean>;
    quarantine(principal: RiskPrincipal, reasons: readonly RiskSignalType[]): Promise<SessionRiskState>;
    release(principal: RiskPrincipal): Promise<void>;
    private actionFor;
    private thresholdFor;
    private incrementSignal;
    private claimFingerprint;
    private isKnown;
    private fingerprint;
    private principalKey;
    private quarantineKey;
    private counterKey;
}
//# sourceMappingURL=sessionRiskService.d.ts.map