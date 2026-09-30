// retry evidence retained on failed apply

pub const RereadOutcome = enum {
    repaired,
    confirmed_mismatch,
    inconsistent_mismatch,
    failed,
};

pub const ConsistencyOutcome = enum {
    resolved,
    unresolved,
    failed,
};

pub const RetrySnapshot = struct {
    started: usize = 0,
    succeeded: usize = 0,

    pub fn hardFailures(snapshot: RetrySnapshot) usize {
        return snapshot.started -| snapshot.succeeded;
    }
};

pub const VerificationSnapshot = struct {
    repaired: usize = 0,
    confirmed_mismatch: usize = 0,
    inconsistent_mismatch: usize = 0,
    failed: usize = 0,

    pub fn total(snapshot: VerificationSnapshot) usize {
        return snapshot.repaired +
            snapshot.confirmed_mismatch +
            snapshot.inconsistent_mismatch +
            snapshot.failed;
    }
};

pub const ConsistencySnapshot = struct {
    resolved: usize = 0,
    unresolved: usize = 0,
    failed: usize = 0,

    pub fn total(snapshot: ConsistencySnapshot) usize {
        return snapshot.resolved + snapshot.unresolved + snapshot.failed;
    }
};

pub const Snapshot = struct {
    reconstruction: RetrySnapshot = .{},
    verification: VerificationSnapshot = .{},
    consistency: ConsistencySnapshot = .{},

    pub fn hasEvents(snapshot: Snapshot) bool {
        return snapshot.reconstruction.started != 0 or
            snapshot.verification.total() != 0 or
            snapshot.consistency.total() != 0;
    }
};

pub const Counters = struct {
    evidence: Snapshot = .{},

    pub fn retryStarted(counters: *Counters) void {
        counters.evidence.reconstruction.started += 1;
    }

    pub fn retrySucceeded(counters: *Counters) void {
        counters.evidence.reconstruction.succeeded += 1;
    }

    pub fn verificationReread(counters: *Counters, outcome: RereadOutcome) void {
        const value = switch (outcome) {
            .repaired => &counters.evidence.verification.repaired,
            .confirmed_mismatch => &counters.evidence.verification.confirmed_mismatch,
            .inconsistent_mismatch => &counters.evidence.verification.inconsistent_mismatch,
            .failed => &counters.evidence.verification.failed,
        };
        value.* += 1;
    }

    pub fn consistencyReread(counters: *Counters, outcome: ConsistencyOutcome) void {
        const value = switch (outcome) {
            .resolved => &counters.evidence.consistency.resolved,
            .unresolved => &counters.evidence.consistency.unresolved,
            .failed => &counters.evidence.consistency.failed,
        };
        value.* += 1;
    }

    pub fn snapshot(counters: *const Counters) Snapshot {
        return counters.evidence;
    }
};
