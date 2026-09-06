package secret

import (
	"context"

	"github.com/marstack-labs/marstack-secrets/internal/platform/crypto"
)

const rewrapBatch = 100

type Rewrapper func(tenant, path string, version int, envelope crypto.Envelope) (crypto.Envelope, bool, error)

type RewrapProgress struct {
	Examined  int
	Rewrapped int
}

type cursor struct {
	tenant  string
	path    string
	version int
}

func (s *Store) Rewrap(ctx context.Context, rewrap Rewrapper) (RewrapProgress, error) {
	if rewrap == nil {
		return RewrapProgress{}, ErrNoRewrapper
	}

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

		for _, record := range batch {
			if err := ctx.Err(); err != nil {
				return progress, err
			}
			at = cursor{tenant: record.Tenant, path: record.Path, version: record.Version}
			progress.Examined++

			envelope, changed, err := rewrap(record.Tenant, record.Path, record.Version, record.Envelope)
			if err != nil {
				return progress, err
			}
			if !changed {
				continue
			}

			written, err := s.replaceWrapping(ctx, record, envelope)
			if err != nil {
				return progress, err
			}
			if written {
				progress.Rewrapped++
			}
		}
	}
}

func (s *Store) rewrapBatch(ctx context.Context, at cursor) ([]Record, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT tenant, path, version, kek_version, wrapped_dek, ciphertext
		 FROM secret_versions
		 WHERE destroyed_at IS NULL AND (tenant, path, version) > (?, ?, ?)
		 ORDER BY tenant, path, version
		 LIMIT ?`,
		at.tenant, at.path, at.version, rewrapBatch)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	batch := make([]Record, 0, rewrapBatch)
	for rows.Next() {
		var record Record
		if err := rows.Scan(
			&record.Tenant,
			&record.Path,
			&record.Version,
			&record.Envelope.KEKVersion,
			&record.Envelope.WrappedDEK,
			&record.Envelope.Ciphertext,
		); err != nil {
			return nil, err
		}
		batch = append(batch, record)
	}
	return batch, rows.Err()
}

func (s *Store) replaceWrapping(ctx context.Context, record Record, envelope crypto.Envelope) (bool, error) {
	result, err := s.db.ExecContext(ctx,
		`UPDATE secret_versions SET kek_version = ?, wrapped_dek = ?
		 WHERE tenant = ? AND path = ? AND version = ?
		   AND kek_version = ? AND destroyed_at IS NULL`,
		envelope.KEKVersion, envelope.WrappedDEK,
		record.Tenant, record.Path, record.Version, record.Envelope.KEKVersion)
	if err != nil {
		return false, err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	return affected == 1, nil
}

func (s *Service) Rewrap(ctx context.Context) (RewrapProgress, error) {
	return s.store.Rewrap(ctx, func(tenant, path string, version int, envelope crypto.Envelope) (crypto.Envelope, bool, error) {
		return s.cipher.Rewrap(ctx, tenant, envelope, locate(tenant, path, version))
	})
}
