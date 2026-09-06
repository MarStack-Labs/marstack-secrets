package param

import (
	"context"

	"github.com/marstack-labs/marstack-secrets/internal/platform/crypto"
)

const rewrapBatch = 100

type RewrapProgress struct {
	Examined  int
	Rewrapped int
}

type cursor struct {
	tenant string
	path   string
}

type wrapping struct {
	tenant   string
	path     string
	envelope crypto.Envelope
}

func (s *Store) Rewrap(ctx context.Context) (RewrapProgress, error) {
	var progress RewrapProgress
	var at cursor

	for {
		batch, err := s.rewrapBatch(ctx, at)
		if err != nil {
			return progress, err
		}
		if len(batch) == 0 {
			return progress, nil
		}

		for _, stored := range batch {
			if err := ctx.Err(); err != nil {
				return progress, err
			}
			at = cursor{tenant: stored.tenant, path: stored.path}
			progress.Examined++

			envelope, changed, err := s.cipher.Rewrap(ctx, stored.tenant, stored.envelope,
				locate(stored.tenant, stored.path))
			if err != nil {
				return progress, err
			}
			if !changed {
				continue
			}

			written, err := s.replaceWrapping(ctx, stored, envelope)
			if err != nil {
				return progress, err
			}
			if written {
				progress.Rewrapped++
			}
		}
	}
}

func (s *Store) rewrapBatch(ctx context.Context, at cursor) ([]wrapping, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT tenant, path, kek_version, wrapped_dek, ciphertext
		 FROM param_values
		 WHERE (tenant, path) > (?, ?)
		 ORDER BY tenant, path
		 LIMIT ?`,
		at.tenant, at.path, rewrapBatch)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	batch := make([]wrapping, 0, rewrapBatch)
	for rows.Next() {
		var stored wrapping
		if err := rows.Scan(
			&stored.tenant,
			&stored.path,
			&stored.envelope.KEKVersion,
			&stored.envelope.WrappedDEK,
			&stored.envelope.Ciphertext,
		); err != nil {
			return nil, err
		}
		batch = append(batch, stored)
	}
	return batch, rows.Err()
}

func (s *Store) replaceWrapping(ctx context.Context, stored wrapping, envelope crypto.Envelope) (bool, error) {
	result, err := s.db.ExecContext(ctx,
		`UPDATE param_values SET kek_version = ?, wrapped_dek = ?
		 WHERE tenant = ? AND path = ? AND kek_version = ?`,
		envelope.KEKVersion, envelope.WrappedDEK,
		stored.tenant, stored.path, stored.envelope.KEKVersion)
	if err != nil {
		return false, err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	return affected == 1, nil
}
