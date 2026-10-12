-- Exact CURRENT_DDL from bridge-core schema5 at b1104b8; immutable migration fixture.

CREATE TABLE IF NOT EXISTS schema_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS counters (
    name TEXT PRIMARY KEY,
    value INTEGER NOT NULL
);
INSERT OR IGNORE INTO counters (name, value) VALUES
    ('acceptance_seq', 0), ('attempt_seq', 0), ('incident_seq', 0),
    ('evidence_seq', 0), ('audit_seq', 0), ('retained_events', 0);
CREATE TABLE IF NOT EXISTS events (
    publisher_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    envelope_hash TEXT NOT NULL,
    envelope_json BLOB NOT NULL,
    state TEXT NOT NULL,
    acceptance_seq INTEGER NOT NULL,
    accepted_at_ms INTEGER NOT NULL,
    expires_at_ms INTEGER,
    recipient TEXT NOT NULL DEFAULT '',
    policy_class TEXT NOT NULL DEFAULT '',
    delivery TEXT NOT NULL DEFAULT 'unhanded',
    attempt_seq INTEGER,
    mode TEXT NOT NULL DEFAULT '',
    scope_key TEXT NOT NULL DEFAULT '',
    revision INTEGER,
    predecessor TEXT,
    predecessor_waived INTEGER NOT NULL DEFAULT 0,
    attempts_made INTEGER NOT NULL DEFAULT 0,
    not_before_ms INTEGER NOT NULL DEFAULT 0,
    duplicate_risk INTEGER NOT NULL DEFAULT 0,
    lineage_key TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (publisher_id, event_id)
);
CREATE TABLE IF NOT EXISTS watermarks (
    publisher_id TEXT NOT NULL,
    recipient TEXT NOT NULL,
    kind TEXT NOT NULL,
    mode TEXT NOT NULL,
    project TEXT NOT NULL,
    task TEXT NOT NULL,
    stream_id TEXT NOT NULL,
    revision INTEGER NOT NULL,
    PRIMARY KEY (publisher_id, recipient, kind, mode, project, task, stream_id)
);
CREATE TABLE IF NOT EXISTS attempts (
    attempt_seq INTEGER PRIMARY KEY,
    state TEXT NOT NULL,
    requested_mode TEXT NOT NULL,
    effective_mode TEXT NOT NULL,
    recipient TEXT NOT NULL,
    actor TEXT NOT NULL,
    endpoint_epoch INTEGER NOT NULL,
    granted TEXT NOT NULL,
    manifest TEXT NOT NULL,
    manifest_hash TEXT NOT NULL,
    lease_expires_ms INTEGER,
    deadline_ms INTEGER NOT NULL,
    recheck_ms INTEGER,
    duplicate_risk INTEGER NOT NULL DEFAULT 0,
    created_ms INTEGER NOT NULL,
    updated_ms INTEGER NOT NULL,
    note TEXT,
    proof_ref TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS attempt_members (
    attempt_seq INTEGER NOT NULL,
    ordinal INTEGER NOT NULL,
    publisher_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    envelope_hash TEXT NOT NULL,
    PRIMARY KEY (attempt_seq, ordinal)
);
CREATE TABLE IF NOT EXISTS incidents (
    incident_seq INTEGER PRIMARY KEY,
    publisher_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    attempt_seq INTEGER,
    kind TEXT NOT NULL,
    reason TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'open',
    created_ms INTEGER NOT NULL,
    updated_ms INTEGER NOT NULL,
    next_check_ms INTEGER,
    review_deadline_ms INTEGER,
    responsible TEXT NOT NULL DEFAULT '',
    resolution TEXT,
    resolved_ms INTEGER,
    duplicate_risk INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS evidence (
    evidence_seq INTEGER PRIMARY KEY,
    publisher_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    attempt_seq INTEGER NOT NULL,
    tier TEXT NOT NULL,
    detail TEXT NOT NULL,
    at_ms INTEGER NOT NULL,
    UNIQUE (publisher_id, event_id, attempt_seq, tier)
);
CREATE TABLE IF NOT EXISTS recipient_policies (
    recipient TEXT PRIMARY KEY,
    no_wake INTEGER NOT NULL,
    reason TEXT,
    set_ms INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS recipient_holds (
    recipient TEXT PRIMARY KEY,
    reason TEXT NOT NULL,
    since_ms INTEGER NOT NULL,
    updated_ms INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS bindings (
    recipient TEXT PRIMARY KEY,
    endpoint_epoch INTEGER NOT NULL,
    inject_capable INTEGER NOT NULL,
    message_capable INTEGER NOT NULL,
    updated_ms INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS source_tags (
    publisher_id TEXT PRIMARY KEY,
    tag TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit (
    audit_seq INTEGER PRIMARY KEY,
    at_ms INTEGER NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    publisher_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    detail TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS stream_lineages (
    lineage_key TEXT PRIMARY KEY,
    owner TEXT NOT NULL,
    set_ms INTEGER NOT NULL,
    note TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS events_by_lineage
    ON events (lineage_key, policy_class, delivery) WHERE lineage_key != '';
CREATE INDEX IF NOT EXISTS events_dispatch
    ON events (state, delivery, recipient, policy_class, acceptance_seq);
CREATE INDEX IF NOT EXISTS events_scope
    ON events (scope_key, state, delivery, revision) WHERE scope_key != '';
CREATE INDEX IF NOT EXISTS events_predecessor
    ON events (publisher_id, predecessor) WHERE predecessor IS NOT NULL;
CREATE INDEX IF NOT EXISTS events_expiry
    ON events (expires_at_ms) WHERE state = 'pending' AND expires_at_ms IS NOT NULL;
CREATE INDEX IF NOT EXISTS attempts_open
    ON attempts (state, lease_expires_ms);
CREATE INDEX IF NOT EXISTS attempt_members_event
    ON attempt_members (publisher_id, event_id);
CREATE UNIQUE INDEX IF NOT EXISTS incidents_one_open
    ON incidents (publisher_id, event_id, kind) WHERE state = 'open';
CREATE INDEX IF NOT EXISTS incidents_by_state
    ON incidents (state, next_check_ms);
