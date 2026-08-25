package seal

import "github.com/marstack-labs/marstack-secrets/internal/platform/sqlite"

const moduleName = "seal"

var migrations = []sqlite.Migration{
	{
		Name: "0001_seal_config",
		SQL: `
			CREATE TABLE seal_config (
				id               INTEGER PRIMARY KEY CHECK (id = 1),
				shamir_shares    INTEGER NOT NULL,
				shamir_threshold INTEGER NOT NULL,
				key_check        BLOB NOT NULL,
				created_at       TEXT NOT NULL
			);
		`,
	},
}
