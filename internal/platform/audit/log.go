package audit

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	dirPerm     = 0o700
	filePerm    = 0o600
	maxLineSize = 1 << 20
)

type Sink interface {
	Append(ctx context.Context, event Event) error
}

type Options struct {
	Now func() time.Time
}

type Log struct {
	mu       sync.Mutex
	file     *os.File
	writer   *bufio.Writer
	sequence int64
	previous string
	now      func() time.Time
	closed   bool
}

func Open(path string, opts Options) (*Log, error) {
	if path == "" {
		return nil, ErrEmptyPath
	}
	if err := os.MkdirAll(filepath.Dir(path), dirPerm); err != nil {
		return nil, err
	}

	tip, err := readTip(path)
	if err != nil {
		return nil, err
	}

	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, filePerm)
	if err != nil {
		return nil, err
	}
	if err := file.Chmod(filePerm); err != nil {
		return nil, errors.Join(err, file.Close())
	}

	log := &Log{
		file:     file,
		writer:   bufio.NewWriter(file),
		sequence: tip.sequence,
		previous: tip.hash,
		now:      opts.Now,
	}
	if log.now == nil {
		log.now = time.Now
	}
	return log, nil
}

func (l *Log) Append(_ context.Context, event Event) error {
	if err := event.validate(); err != nil {
		return err
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	if l.closed {
		return ErrClosed
	}

	record := newRecord(l.sequence+1, l.now(), event, l.previous)
	line, err := record.encode()
	if err != nil {
		return err
	}

	if _, err := l.writer.Write(line); err != nil {
		return err
	}
	if err := l.writer.Flush(); err != nil {
		return err
	}
	if err := l.file.Sync(); err != nil {
		return err
	}

	l.sequence = record.Sequence
	l.previous = record.Hash
	return nil
}

func (l *Log) Sequence() int64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.sequence
}

func (l *Log) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.closed {
		return nil
	}
	l.closed = true

	return errors.Join(l.writer.Flush(), l.file.Sync(), l.file.Close())
}

type tip struct {
	sequence int64
	hash     string
}

func readTip(path string) (tip, error) {
	report, err := Verify(path)
	if errors.Is(err, os.ErrNotExist) {
		return tip{sequence: 0, hash: Genesis}, nil
	}
	if err != nil {
		return tip{}, err
	}
	return tip{sequence: report.Records, hash: report.LastHash}, nil
}

type Report struct {
	Records  int64
	LastHash string
}

func Verify(path string) (Report, error) {
	if path == "" {
		return Report{}, ErrEmptyPath
	}

	file, err := os.Open(path)
	if err != nil {
		return Report{}, err
	}
	defer func() { _ = file.Close() }()

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64<<10), maxLineSize)

	var report Report
	expected := int64(1)
	previous := Genesis

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var record Record
		if err := json.Unmarshal(line, &record); err != nil {
			return Report{}, fmt.Errorf("%w: record %d is not readable", ErrBroken, expected)
		}
		if record.Sequence != expected {
			return Report{}, fmt.Errorf("%w: expected record %d but found %d", ErrBroken, expected, record.Sequence)
		}
		if record.PrevHash != previous {
			return Report{}, fmt.Errorf("%w: record %d does not follow record %d", ErrBroken, record.Sequence, expected-1)
		}
		if record.chain() != record.Hash {
			return Report{}, fmt.Errorf("%w: record %d has been altered", ErrBroken, record.Sequence)
		}

		previous = record.Hash
		report.Records = record.Sequence
		expected++
	}

	if err := scanner.Err(); err != nil {
		if errors.Is(err, bufio.ErrTooLong) {
			return Report{}, fmt.Errorf("%w: record %d is too long to be genuine", ErrBroken, expected)
		}
		if errors.Is(err, io.ErrUnexpectedEOF) {
			return Report{}, fmt.Errorf("%w: the log ends mid record", ErrBroken)
		}
		return Report{}, err
	}

	report.LastHash = previous
	return report, nil
}
