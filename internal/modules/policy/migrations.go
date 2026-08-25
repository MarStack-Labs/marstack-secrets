package policy

import "github.com/marstack-labs/marstack-secrets/internal/platform/sqlite"

const moduleName = "policy"

var migrations = []sqlite.Migration{
	{
		Name: "0001_definitions_and_bindings",
		SQL: `
			CREATE TABLE policy_definitions (
				tenant     TEXT NOT NULL,
				name       TEXT NOT NULL,
				rules      TEXT NOT NULL,
				created_at TEXT NOT NULL,
				updated_at TEXT NOT NULL,
				PRIMARY KEY (tenant, name)
			);

			CREATE TABLE policy_bindings (
				tenant      TEXT NOT NULL,
				identity_id TEXT NOT NULL,
				policy_name TEXT NOT NULL,
				created_at  TEXT NOT NULL,
				PRIMARY KEY (tenant, identity_id, policy_name),
				FOREIGN KEY (tenant, policy_name)
					REFERENCES policy_definitions (tenant, name)
					ON DELETE CASCADE
			);

			CREATE INDEX policy_bindings_by_identity ON policy_bindings (identity_id);
		`,
	},
}
