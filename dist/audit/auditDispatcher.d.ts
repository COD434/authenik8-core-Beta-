import type { AuditConfig, AuditEmitter, AuditEventInput } from "./types";
export declare class AuditDeliveryError extends Error {
    readonly causes: readonly unknown[];
    constructor(causes: readonly unknown[]);
}
export declare class AuditDispatcher implements AuditEmitter {
    private readonly sinks;
    private readonly delivery;
    private readonly onDeliveryError;
    constructor(config?: AuditConfig);
    emit(input: AuditEventInput): Promise<void>;
}
//# sourceMappingURL=auditDispatcher.d.ts.map