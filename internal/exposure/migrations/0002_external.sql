-- Exposure-Check, Spur 2 "Erreichbar": Weiterleitungen, die der Router meldet (UPnP), und vom Nutzer erwartete Ports.
-- evidence: woher die Aussage stammt (upnp; spaeter probe = Außen-Messpunkt). state: open | gone.
-- internal_addr / internal_port: Ziel der Weiterleitung im LAN.
CREATE TABLE IF NOT EXISTS exposure_external (
	proto         TEXT NOT NULL,
	port          INTEGER NOT NULL,
	evidence      TEXT NOT NULL DEFAULT 'upnp',
	internal_addr TEXT NOT NULL DEFAULT '',
	internal_port INTEGER NOT NULL DEFAULT 0,
	description   TEXT NOT NULL DEFAULT '',
	state         TEXT NOT NULL DEFAULT 'open',
	first_seen    TEXT NOT NULL,
	last_seen     TEXT NOT NULL,
	PRIMARY KEY (proto, port, evidence)
);

-- Ports, die der Nutzer als erwartet eingetragen hat (Protokoll und externer Port).
CREATE TABLE IF NOT EXISTS exposure_expected (
	proto      TEXT NOT NULL,
	port       INTEGER NOT NULL,
	note       TEXT NOT NULL DEFAULT '',
	created_at TEXT NOT NULL,
	PRIMARY KEY (proto, port)
);
