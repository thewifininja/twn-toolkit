PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;
CREATE TABLE audit_events (
    id TEXT PRIMARY KEY,
    recorded_at REAL NOT NULL,
    user_id TEXT NOT NULL,
    username TEXT NOT NULL,
    remote_ip TEXT NOT NULL,
    method TEXT NOT NULL,
    endpoint TEXT NOT NULL,
    path TEXT NOT NULL,
    status_code INTEGER NOT NULL
);
INSERT INTO audit_events VALUES(
    'e25307f1c1514d1165b1b715',1784124699.080984115,
    '51f14dbdc9d769d79871564ba898276d','fixture-admin','127.0.0.1',
    'POST','legacy_save','/legacy',302
);
CREATE TABLE audit_event_details (
    audit_event_id TEXT PRIMARY KEY,
    category TEXT NOT NULL DEFAULT '',
    action TEXT NOT NULL DEFAULT '',
    summary TEXT NOT NULL DEFAULT '',
    resource_type TEXT NOT NULL DEFAULT '',
    resource_id TEXT NOT NULL DEFAULT '',
    resource_name TEXT NOT NULL DEFAULT '',
    detail_json TEXT NOT NULL DEFAULT '{}'
);
INSERT INTO audit_event_details VALUES(
    'e25307f1c1514d1165b1b715','','','','','','','{}'
);
CREATE INDEX audit_events_recent ON audit_events(recorded_at DESC);
COMMIT;
