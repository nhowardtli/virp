PRAGMA journal_mode=DELETE;
PRAGMA synchronous=FULL;
CREATE TABLE policy_control (
 id INTEGER PRIMARY KEY CHECK(id=1), version INTEGER NOT NULL CHECK(version=1),
 stopped INTEGER NOT NULL CHECK(stopped IN(0,1)),
 calls INTEGER NOT NULL CHECK(calls>=0), disruptive INTEGER NOT NULL CHECK(disruptive>=0),
 last_time INTEGER NOT NULL CHECK(last_time>=0)
);
INSERT INTO policy_control VALUES(1,1,0,0,0,0);
CREATE TABLE policy_attempts (
 id INTEGER PRIMARY KEY AUTOINCREMENT, uid INTEGER NOT NULL, device_id INTEGER NOT NULL,
 operation TEXT NOT NULL, resource TEXT NOT NULL, command TEXT NOT NULL,
 policy_hash TEXT NOT NULL, state TEXT NOT NULL CHECK(state IN('pending','unknown','done','reconciled')),
 created INTEGER NOT NULL
);
CREATE TABLE policy_owner_events (
 id INTEGER PRIMARY KEY AUTOINCREMENT, created INTEGER NOT NULL,
 action TEXT NOT NULL, attempt_id INTEGER, evidence TEXT NOT NULL
);
