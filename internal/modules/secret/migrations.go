package secret

import "github.com/marstack-labs/marstack-secrets/internal/platform/sqlite"

const moduleName = "secret"

var migrations = []sqlite.Migration{
	{
		Name: "0001_versioned_secrets",
		SQL: `
			CREATE TABLE secret_metadata (
				tenant          TEXT NOT NULL,
				path            TEXT NOT NULL,
				current_version INTEGER NOT NULL,
				max_versions    INTEGER NOT NULL,
				created_at      TEXT NOT NULL,
				updated_at      TEXT NOT NULL,
				PRIMARY KEY (tenant, path)
			);

			CREATE TABLE secret_versions (
				tenant       TEXT NOT NULL,
				path         TEXT NOT NULL,
				version      INTEGER NOT NULL,
				kek_version  INTEGER NOT NULL,
				wrapped_dek  BLOB NOT NULL,
				ciphertext   BLOB NOT NULL,
				created_at   TEXT NOT NULL,
				deleted_at   TEXT,
				destroyed_at TEXT,
				PRIMARY KEY (tenant, path, version),
				FOREIGN KEY (tenant, path)
					REFERENCES secret_metadata (tenant, path)
					ON DELETE CASCADE
			);
		`,
	},
}
