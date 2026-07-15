PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;
CREATE TABLE activity_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
INSERT INTO activity_meta VALUES('schema_version','1');
INSERT INTO activity_meta VALUES('legacy_json_imported','1');
CREATE TABLE activity_users (
    user_id TEXT PRIMARY KEY,
    username TEXT NOT NULL
);
INSERT INTO activity_users VALUES('51f14dbdc9d769d79871564ba898276d','fixture-admin');
CREATE TABLE activity_samples (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    recorded_at INTEGER NOT NULL,
    category TEXT NOT NULL,
    counter TEXT NOT NULL,
    amount INTEGER NOT NULL CHECK (amount >= 0),
    user_id TEXT NOT NULL DEFAULT ''
);
INSERT INTO activity_samples VALUES(1,1784124699,'actions','total',1,'51f14dbdc9d769d79871564ba898276d');
INSERT INTO activity_samples VALUES(2,1784124699,'snmp','polls',1,'51f14dbdc9d769d79871564ba898276d');
CREATE TABLE activity_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    recorded_at INTEGER NOT NULL,
    category TEXT NOT NULL,
    title TEXT NOT NULL,
    detail TEXT NOT NULL DEFAULT '',
    user_id TEXT NOT NULL DEFAULT '',
    username TEXT NOT NULL DEFAULT ''
);
INSERT INTO activity_events VALUES(1,1784124699,'Infrastructure','Legacy SNMP test','1 poll','51f14dbdc9d769d79871564ba898276d','fixture-admin');
INSERT INTO sqlite_sequence VALUES('activity_samples',2);
INSERT INTO sqlite_sequence VALUES('activity_events',1);
CREATE INDEX activity_samples_time_idx ON activity_samples(recorded_at);
CREATE INDEX activity_samples_metric_idx ON activity_samples(category, counter, recorded_at);
CREATE INDEX activity_samples_user_idx ON activity_samples(user_id, recorded_at);
CREATE INDEX activity_events_time_idx ON activity_events(recorded_at DESC);
COMMIT;
