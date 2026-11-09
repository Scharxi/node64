-- Exposure-Check: gesehene offene Ports je Adresse. address = "self" (die Node) oder die IP eines Geraets.
-- state: open | gone (war offen, jetzt nicht mehr). Nur offene Ports werden gespeichert, "zu" steht nicht hier.
CREATE TABLE IF NOT EXISTS exposure_listen (
	address    TEXT NOT NULL,
	proto      TEXT NOT NULL,
	port       INTEGER NOT NULL,
	state      TEXT NOT NULL DEFAULT 'open',
	service    TEXT NOT NULL DEFAULT '',
	bind       TEXT NOT NULL DEFAULT '',
	owner      TEXT NOT NULL DEFAULT '',
	first_seen TEXT NOT NULL,
	last_seen  TEXT NOT NULL,
	source     TEXT NOT NULL,
	PRIMARY KEY (address, proto, port)
);
CREATE INDEX IF NOT EXISTS idx_exposure_listen_address ON exposure_listen(address);
