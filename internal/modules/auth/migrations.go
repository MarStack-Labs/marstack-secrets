package auth

import "github.com/marstack-labs/marstack-secrets/internal/platform/sqlite"

const moduleName = "auth"

var migrations = []sqlite.Migration{
	{
		Name: "0001_identities_and_tokens",
		SQL: `
			CREATE TABLE auth_identities (
				id          TEXT NOT NULL PRIMARY KEY,
				kind        TEXT NOT NULL,
				tenant      TEXT NOT NULL,
				created_at  TEXT NOT NULL,
				disabled_at TEXT
			);

			CREATE TABLE auth_tokens (
				id_hash     BLOB NOT NULL PRIMARY KEY,
				identity_id TEXT NOT NULL,
				binding     TEXT NOT NULL,
				issued_at   TEXT NOT NULL,
				expires_at  TEXT NOT NULL,
				revoked_at  TEXT,
				FOREIGN KEY (identity_id)
					REFERENCES auth_identities (id)
					ON DELETE CASCADE
			);

			CREATE INDEX auth_tokens_by_identity ON auth_tokens (identity_id);
			CREATE INDEX auth_tokens_by_expiry ON auth_tokens (expires_at);
		`,
	},
	{
		Name: "0002_single_use_tokens",
		SQL: `
			ALTER TABLE auth_tokens ADD COLUMN single_use INTEGER NOT NULL DEFAULT 0;
			ALTER TABLE auth_tokens ADD COLUMN consumed_at TEXT;
		`,
	},
	{
		Name: "0003_spent_assertions",
		SQL: `
			CREATE TABLE auth_spent_assertions (
				id         TEXT NOT NULL PRIMARY KEY,
				identity   TEXT NOT NULL,
				spent_at   TEXT NOT NULL,
				expires_at TEXT NOT NULL
			);

			CREATE INDEX auth_spent_assertions_by_expiry ON auth_spent_assertions (expires_at);
		`,
	},
}
