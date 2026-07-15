PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;
CREATE TABLE automations (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 0,
    interval_seconds INTEGER NOT NULL,
    trigger_after INTEGER NOT NULL,
    recover_after INTEGER NOT NULL,
    cooldown_seconds INTEGER NOT NULL DEFAULT 0,
    condition_type TEXT NOT NULL,
    condition_config TEXT NOT NULL,
    actions_encrypted TEXT NOT NULL,
    condition_definition_id TEXT,
    action_definition_ids TEXT,
    action_stages TEXT,
    state TEXT NOT NULL DEFAULT 'disabled',
    consecutive_met INTEGER NOT NULL DEFAULT 0,
    consecutive_clear INTEGER NOT NULL DEFAULT 0,
    next_check_at REAL,
    pending_schedule_at REAL,
    last_check_at REAL,
    last_triggered_at REAL,
    last_summary TEXT,
    last_error TEXT,
    created_by TEXT NOT NULL,
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL
);
INSERT INTO automations VALUES(
    '796f417b43dac5fcbfbd25ea','Legacy manual collection',0,30,1,1,0,
    'manual.trigger','{}',
    'gAAAAABqV5UbwV4wOrakOu5K4ulJHANBUrJg7EZRxALCfkFQPgmpGtiz9pvHjCjvOfpz9awHwX1RKaHEnSPl7_QzNSpHGLlsCqZEH8AY-_kbtoUgYStF0cg6EOnoJ14_2pllSQvjgGK13jziwMMaxdZvVc5U_aDr6ZFOQDHnZ6cEHSh0DxHtoYZK1dM_XYCG2tsC_4B4Vj2nR9EeqPjfP8D3KK8iJzNFtIRFgLFZD7xm-8rZBK5aD6_tkHrCOoTMXh4dk-IZT8v8VpNy049sdU822b35Q-efECVHQh4g3Bz7-ml6QSphq_x7nrV5mEOtv8nGToKlsec0U12aEczJC62JI_8Ky3m84h_ceVppgRIvWE_-kFmuPGw=',
    '08b6d432d01edcc134b55b01','["bbb6b392b1bab706e00918f0"]',
    '[{"id":"stage-1","name":"Stage 1","continue_policy":"all_completed","action_definition_ids":["bbb6b392b1bab706e00918f0"]}]',
    'disabled',0,0,NULL,NULL,NULL,NULL,NULL,NULL,
    '51f14dbdc9d769d79871564ba898276d',1784124699.079525947,1784124699.079525947
);
CREATE TABLE automation_conditions (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL COLLATE NOCASE UNIQUE,
    type TEXT NOT NULL,
    config_json TEXT NOT NULL,
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL
);
INSERT INTO automation_conditions VALUES(
    '08b6d432d01edcc134b55b01','Legacy manual collection condition',
    'manual.trigger','{}',1784124699.070400954,1784124699.070400954
);
CREATE TABLE automation_actions (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL COLLATE NOCASE UNIQUE,
    type TEXT NOT NULL,
    config_encrypted TEXT NOT NULL,
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL
);
INSERT INTO automation_actions VALUES(
    'bbb6b392b1bab706e00918f0','Legacy manual collection action','ssh.collect',
    'gAAAAABqV5UbCBEDGH6y3tpRWjgU8LwuBh88cVJf16MobTw8MZRU-mLztZgLBh-b8fDwvSnxEKwz4msWXX-HYYfY3jsb5OtubXqB8yAdm9egZyEsLzKnFlY83uRhSDzkDLgjYqesSX2sKE8cYPaU0aSAnt6jnBi3rIYySQjEaS_rz3CpYgjr-Hg3uGQDpVn6wGqccGB9ZRBfPONMy1y-9Ad26gR3fgdp1eniLXwAOtSfCBKcPNQvYJ3ctsMZIyXwxXt7cvFyQFtH1wDj3aSLC5JSF-r3Uo4lOjGb6hPpP2a_xnWJUN_rXVONVhGeTkQsEH2hWdFOLqod',
    1784124699.071156979,1784124699.071156979
);
CREATE TABLE automation_checks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    automation_id TEXT NOT NULL REFERENCES automations(id) ON DELETE CASCADE,
    checked_at REAL NOT NULL,
    met INTEGER NOT NULL,
    status TEXT NOT NULL,
    summary TEXT NOT NULL,
    evidence_json TEXT NOT NULL
);
CREATE TABLE automation_runs (
    id TEXT PRIMARY KEY,
    automation_id TEXT NOT NULL REFERENCES automations(id) ON DELETE CASCADE,
    started_at REAL NOT NULL,
    finished_at REAL,
    status TEXT NOT NULL,
    trigger_summary TEXT NOT NULL,
    results_json TEXT NOT NULL
);
CREATE TABLE automation_schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at REAL NOT NULL,
    description TEXT NOT NULL
);
INSERT INTO automation_schema_migrations VALUES(
    1,1784124647.623066186,'Add ordered parallel action stages'
);
INSERT INTO automation_schema_migrations VALUES(
    2,1784124647.6230762,'Normalize SNMP conditions into per-host AND rules'
);
INSERT INTO automation_schema_migrations VALUES(
    3,1784124647.62307787,'Add configurable automation history retention'
);
CREATE TABLE automation_settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at REAL NOT NULL
);
INSERT INTO automation_settings VALUES('check_retention_days','7',1784124647.62307787);
INSERT INTO automation_settings VALUES('run_retention_days','0',1784124647.62307787);
INSERT INTO automation_settings VALUES('last_pruned_at','0',1784124647.62307787);
CREATE INDEX automations_due ON automations(enabled, next_check_at);
CREATE INDEX automation_checks_recent ON automation_checks(automation_id, checked_at DESC);
CREATE INDEX automation_runs_recent ON automation_runs(automation_id, started_at DESC);
COMMIT;
