package param

import "github.com/marstack-labs/marstack-secrets/internal/platform/sqlite"

const moduleName = "param"

var migrations = []sqlite.Migration{
	{
		Name: "0001_parameters",
		SQL: `
			CREATE TABLE param_values (
				tenant      TEXT NOT NULL,
				path        TEXT NOT NULL,
				kind        TEXT NOT NULL,
				kek_version INTEGER NOT NULL,
				wrapped_dek BLOB NOT NULL,
				ciphertext  BLOB NOT NULL,
				updated_at  TEXT NOT NULL,
				updated_by  TEXT NOT NULL,
				PRIMARY KEY (tenant, path)
			);
		`,
	},
}
