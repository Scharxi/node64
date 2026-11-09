-- IPAM: Subnetze und Adressen. Die Scan-Spalten kommen mit der Scan-Phase (eigene Migration).

-- Subnetze: cidr ist das maskierte Netz (192.168.1.0/24); baseline_at = erster Durchlauf, der das Netz gesehen hat
CREATE TABLE IF NOT EXISTS ipam_subnets (
	id          INTEGER PRIMARY KEY,
	name        TEXT NOT NULL,
	cidr        TEXT NOT NULL UNIQUE,
	note        TEXT NOT NULL DEFAULT '',
	baseline_at TEXT NOT NULL DEFAULT '',
	created_at  TEXT NOT NULL,
	updated_at  TEXT NOT NULL
);

-- Adressen: name = von Hand, source_name = aus einer Quelle (Handeingabe schlaegt Quelle),
-- mac = zuletzt gesehen, reserved_mac = von Hand gesetzt (nur damit wird ein Konflikt erkannt),
-- auto_known = IPv6-Adresse einer MAC, die an einer bekannten Adresse haengt
CREATE TABLE IF NOT EXISTS ipam_addresses (
	id           INTEGER PRIMARY KEY,
	subnet_id    INTEGER NOT NULL,
	ip           TEXT NOT NULL,
	name         TEXT NOT NULL DEFAULT '',
	source_name  TEXT NOT NULL DEFAULT '',
	mac          TEXT NOT NULL DEFAULT '',
	reserved_mac TEXT NOT NULL DEFAULT '',
	note         TEXT NOT NULL DEFAULT '',
	reserved     INTEGER NOT NULL DEFAULT 0,
	acknowledged INTEGER NOT NULL DEFAULT 0,
	ignored      INTEGER NOT NULL DEFAULT 0,
	auto_known   INTEGER NOT NULL DEFAULT 0,
	first_seen   TEXT NOT NULL DEFAULT '',
	last_seen    TEXT NOT NULL DEFAULT '',
	last_source  TEXT NOT NULL DEFAULT '',
	created_at   TEXT NOT NULL,
	UNIQUE (subnet_id, ip)
);
CREATE INDEX IF NOT EXISTS idx_ipam_addresses_subnet ON ipam_addresses(subnet_id);
