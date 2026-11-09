-- Exposure-Check: Verlauf. Ein Ereignis je Uebergang einer Zeile (neu, wieder offen, weg), geschrieben in derselben
-- Transaktion wie die Aenderung. kind: forward_new | forward_gone | listen_new | listen_gone.
-- notified: 0 = noch nicht fuer eine Meldung ausgewertet, 1 = ausgewertet ohne Meldung, 2 = ausgewertet und gemeldet.
CREATE TABLE IF NOT EXISTS exposure_events (
	id       INTEGER PRIMARY KEY,
	at       TEXT NOT NULL,
	kind     TEXT NOT NULL,
	proto    TEXT NOT NULL,
	port     INTEGER NOT NULL,
	address  TEXT NOT NULL DEFAULT '',
	detail   TEXT NOT NULL DEFAULT '',
	notified INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_exposure_events_at ON exposure_events(at);

-- Baseline: eine Adresse, die einmal aufgenommen wurde (auch ohne offene Ports). Erst danach zaehlt ein neuer offener Port als Ereignis.
CREATE TABLE IF NOT EXISTS exposure_seen (
	address TEXT PRIMARY KEY,
	at      TEXT NOT NULL
);
