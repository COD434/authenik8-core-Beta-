"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.SessionRiskService = void 0;
const crypto_1 = require("crypto");
const keyNamespace_1 = require("../redis/keyNamespace");
const safeString_1 = require("../utility/safeString");
const DEFAULT_SIGNAL_WINDOW_SECONDS = 5 * 60;
const DEFAULT_QUARANTINE_SECONDS = 15 * 60;
const DEFAULT_CONCURRENT_REFRESH_THRESHOLD = 2;
const DEFAULT_SUSPICIOUS_AGENT_THRESHOLD = 5;
const MAX_RISK_IDENTIFIER_LENGTH = 256;
const MAX_RISK_FINGERPRINT_LENGTH = 512;
const MAX_RISK_STATE_BYTES = 4096;
const SIGNAL_TYPES = [
    "refresh_replay",
    "concurrent_refresh",
    "ip_change",
    "device_change",
    "suspicious_agent_activity",
];
const SIGNAL_TYPE_SET = new Set(SIGNAL_TYPES);
const CONTEXT_ACTIONS = new Set([
    "ignore",
    "audit",
    "quarantine",
]);
const activeState = () => ({
    status: "active",
    reasons: [],
});
const positiveInteger = (value, fallback, name, maximum = 366 * 24 * 60 * 60) => {
    const resolved = value ?? fallback;
    if (!Number.isSafeInteger(resolved) ||
        resolved <= 0 ||
        resolved > maximum) {
        throw new Error(`${name} must be between 1 and ${maximum}`);
    }
    return resolved;
};
const validatePrincipal = (principal) => {
    if (!principal ||
        (principal.kind !== "human" && principal.kind !== "agent") ||
        typeof principal.id !== "string" ||
        principal.id.length === 0 ||
        principal.id.length > MAX_RISK_IDENTIFIER_LENGTH ||
        (0, safeString_1.containsControlCharacter)(principal.id) ||
        typeof principal.sessionId !== "string" ||
        principal.sessionId.length === 0 ||
        principal.sessionId.length > MAX_RISK_IDENTIFIER_LENGTH ||
        (0, safeString_1.containsControlCharacter)(principal.sessionId)) {
        throw new Error("Risk principal is invalid");
    }
};
const validateSignalType = (value) => {
    if (!SIGNAL_TYPE_SET.has(value)) {
        throw new Error("Risk signal type is invalid");
    }
    return value;
};
const parseRiskState = (stored) => {
    if (stored.length > MAX_RISK_STATE_BYTES ||
        Buffer.byteLength(stored, "utf8") > MAX_RISK_STATE_BYTES) {
        throw new Error("Stored risk state exceeds the size limit");
    }
    let value;
    try {
        value = JSON.parse(stored);
    }
    catch {
        throw new Error("Stored risk state is invalid");
    }
    if (!value || typeof value !== "object") {
        throw new Error("Stored risk state is invalid");
    }
    const candidate = value;
    if (candidate.status !== "quarantined" ||
        !Array.isArray(candidate.reasons) ||
        candidate.reasons.length === 0 ||
        candidate.reasons.length > SIGNAL_TYPES.length ||
        candidate.reasons.some((reason) => !SIGNAL_TYPE_SET.has(reason)) ||
        new Set(candidate.reasons).size !== candidate.reasons.length ||
        typeof candidate.quarantinedAt !== "string" ||
        !Number.isFinite(Date.parse(candidate.quarantinedAt)) ||
        typeof candidate.expiresAt !== "string" ||
        !Number.isFinite(Date.parse(candidate.expiresAt))) {
        throw new Error("Stored risk state is invalid");
    }
    return {
        status: "quarantined",
        reasons: [...candidate.reasons],
        quarantinedAt: candidate.quarantinedAt,
        expiresAt: candidate.expiresAt,
    };
};
class SessionRiskService {
    constructor(store, config = {}, audit, keyPrefix = "authenik8:risk") {
        this.store = store;
        this.audit = audit;
        this.keyPrefix = (0, keyNamespace_1.validateRedisKeyPrefix)(keyPrefix);
        if (config.enabled !== undefined &&
            typeof config.enabled !== "boolean") {
            throw new Error("risk.enabled must be a boolean");
        }
        this.enabled = config.enabled ?? true;
        this.signalWindowSeconds = positiveInteger(config.signalWindowSeconds, DEFAULT_SIGNAL_WINDOW_SECONDS, "risk.signalWindowSeconds");
        this.quarantineSeconds = positiveInteger(config.quarantineSeconds, DEFAULT_QUARANTINE_SECONDS, "risk.quarantineSeconds");
        this.concurrentRefreshThreshold = positiveInteger(config.concurrentRefreshThreshold, DEFAULT_CONCURRENT_REFRESH_THRESHOLD, "risk.concurrentRefreshThreshold", 1000000);
        this.suspiciousAgentThreshold = positiveInteger(config.suspiciousAgentThreshold, DEFAULT_SUSPICIOUS_AGENT_THRESHOLD, "risk.suspiciousAgentThreshold", 1000000);
        this.ipChangeAction = config.ipChangeAction ?? "audit";
        this.deviceChangeAction = config.deviceChangeAction ?? "audit";
        if (!CONTEXT_ACTIONS.has(this.ipChangeAction) ||
            !CONTEXT_ACTIONS.has(this.deviceChangeAction)) {
            throw new Error("Risk context actions must be ignore, audit, or quarantine");
        }
    }
    async report(signal) {
        validatePrincipal(signal.principal);
        validateSignalType(signal.type);
        if (signal.fingerprint !== undefined &&
            (typeof signal.fingerprint !== "string" ||
                signal.fingerprint.length === 0 ||
                signal.fingerprint.length > MAX_RISK_FINGERPRINT_LENGTH ||
                (0, safeString_1.containsControlCharacter)(signal.fingerprint))) {
            throw new Error("Risk signal fingerprint is invalid");
        }
        if (!this.enabled || this.actionFor(signal.type) === "ignore") {
            return this.getState(signal.principal);
        }
        if (signal.fingerprint &&
            !(await this.claimFingerprint(signal.principal, signal))) {
            return this.getState(signal.principal);
        }
        const count = await this.incrementSignal(signal.principal, signal.type);
        const quarantined = count >= this.thresholdFor(signal.type)
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
    async assessContext(principal, expected, observed) {
        validatePrincipal(principal);
        let state = await this.getState(principal);
        const changes = [
            { type: "ip_change", before: expected.ip, after: observed.ip },
            {
                type: "device_change",
                before: expected.device,
                after: observed.device,
            },
        ];
        for (const change of changes) {
            if (!this.isKnown(change.before) ||
                !this.isKnown(change.after) ||
                change.before === change.after) {
                continue;
            }
            state = await this.report({
                type: change.type,
                principal,
                fingerprint: this.fingerprint(change.before, change.after),
                metadata: { changed: change.type === "ip_change" ? "ip" : "device" },
            });
            if (state.status === "quarantined")
                return state;
        }
        return state;
    }
    async getState(principal) {
        validatePrincipal(principal);
        if (!this.enabled)
            return activeState();
        const stored = await this.store.get(this.quarantineKey(principal));
        if (!stored)
            return activeState();
        return parseRiskState(stored);
    }
    async isQuarantined(principal) {
        return (await this.getState(principal)).status === "quarantined";
    }
    async quarantine(principal, reasons) {
        validatePrincipal(principal);
        const validatedReasons = [...new Set(reasons.map(validateSignalType))];
        if (validatedReasons.length === 0) {
            throw new Error("Quarantine requires at least one valid reason");
        }
        const existing = await this.getState(principal);
        const now = new Date();
        const state = {
            status: "quarantined",
            reasons: [...new Set([...existing.reasons, ...validatedReasons])],
            quarantinedAt: existing.quarantinedAt ?? now.toISOString(),
            expiresAt: new Date(now.getTime() + this.quarantineSeconds * 1000).toISOString(),
        };
        await this.store.set(this.quarantineKey(principal), JSON.stringify(state), this.quarantineSeconds);
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
    async release(principal) {
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
    actionFor(type) {
        if (type === "ip_change")
            return this.ipChangeAction;
        if (type === "device_change")
            return this.deviceChangeAction;
        return "quarantine";
    }
    thresholdFor(type) {
        if (type === "refresh_replay")
            return 1;
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
    async incrementSignal(principal, type) {
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
    async claimFingerprint(principal, signal) {
        const fingerprint = (0, crypto_1.createHash)("sha256")
            .update(signal.fingerprint)
            .digest("base64url");
        const key = `${this.principalKey(principal)}:seen:${signal.type}:${fingerprint}`;
        return this.store.setIfAbsent(key, "1", this.signalWindowSeconds);
    }
    isKnown(value) {
        return !!value && value !== "unknown";
    }
    fingerprint(before, after) {
        return (0, crypto_1.createHash)("sha256")
            .update(before)
            .update("\0")
            .update(after)
            .digest("base64url");
    }
    principalKey(principal) {
        const identity = (0, crypto_1.createHash)("sha256")
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
    quarantineKey(principal) {
        return `${this.principalKey(principal)}:quarantine`;
    }
    counterKey(principal, type) {
        return `${this.principalKey(principal)}:count:${type}`;
    }
}
exports.SessionRiskService = SessionRiskService;
//# sourceMappingURL=sessionRiskService.js.map