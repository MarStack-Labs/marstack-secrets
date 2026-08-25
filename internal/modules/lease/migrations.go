package lease

import "github.com/marstack-labs/marstack-secrets/internal/platform/sqlite"

const moduleName = "lease"

var migrations = []sqlite.Migration{
	{
		Name: "0001_lease_records",
		SQL: `
			CREATE TABLE lease_records (
				id          TEXT NOT NULL PRIMARY KEY,
				tenant      TEXT NOT NULL,
				identity_id TEXT NOT NULL,
				path        TEXT NOT NULL,
				version     INTEGER NOT NULL,
				issued_at   TEXT NOT NULL,
				expires_at  TEXT NOT NULL,
				revoked_at  TEXT
			);

			CREATE UNIQUE INDEX lease_records_holder
				ON lease_records (tenant, identity_id, path, version)
				WHERE revoked_at IS NULL;

			CREATE INDEX lease_records_by_path ON lease_records (tenant, path);
			CREATE INDEX lease_records_by_identity ON lease_records (tenant, identity_id);
			CREATE INDEX lease_records_by_expiry ON lease_records (expires_at);
		`,
	},
}
