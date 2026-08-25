package audit

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

var origin = time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)

func newTestLog(t *testing.T) (*Log, string) {
	t.Helper()

	path := filepath.Join(t.TempDir(), "audit", "audit.log")
	log, err := Open(path, Options{Now: func() time.Time { return origin }})
	if err != nil {
		t.Fatalf("Open returned error: %v", err)
	}
	t.Cleanup(func() { _ = log.Close() })
	return log, path
}

func read(t *testing.T, event string) Event {
	t.Helper()
	return Event{
		Operation: event,
		Identity:  "instance/web-01",
		Tenant:    "prod",
		Path:      "secret/prod/payment-api",
		Version:   3,
		Result:    ResultAllow,
		RequestID: "7c1e",
		SourceIP:  "10.0.3.11",
	}
}

func records(t *testing.T, path string) []Record {
	t.Helper()

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading the log: %v", err)
	}

	var found []Record
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if line == "" {
			continue
		}
		var record Record
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatalf("decoding %q: %v", line, err)
		}
		found = append(found, record)
	}
	return found
}

func TestAppendWritesAChainedRecord(t *testing.T) {
	log, path := newTestLog(t)

	if err := log.Append(t.Context(), read(t, "secret.read")); err != nil {
		t.Fatalf("Append returned error: %v", err)
	}
	if err := log.Append(t.Context(), read(t, "secret.write")); err != nil {
		t.Fatalf("Append returned error: %v", err)
	}

	written := records(t, path)
	if len(written) != 2 {
		t.Fatalf("the log holds %d records, want 2", len(written))
	}
	if written[0].Sequence != 1 || written[1].Sequence != 2 {
		t.Errorf("sequences = %d and %d", written[0].Sequence, written[1].Sequence)
	}
	if written[0].PrevHash != Genesis {
		t.Errorf("the first record follows %q, want the genesis value", written[0].PrevHash)
	}
	if written[1].PrevHash != written[0].Hash {
		t.Error("the second record does not follow the first")
	}
	if written[0].Hash == written[1].Hash {
		t.Error("two records share a hash")
	}
}

func TestTheLogNeverHoldsAValue(t *testing.T) {
	log, path := newTestLog(t)

	if err := log.Append(t.Context(), read(t, "secret.read")); err != nil {
		t.Fatalf("Append returned error: %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading the log: %v", err)
	}
	for _, forbidden := range []string{"value", "plaintext", "secret_value"} {
		if strings.Contains(string(raw), `"`+forbidden+`"`) {
			t.Errorf("the log carries a %q field: %s", forbidden, raw)
		}
	}
	if !strings.Contains(string(raw), `"version":3`) {
		t.Error("the log does not record which version was read")
	}
}

func TestVerifyAcceptsAGenuineLog(t *testing.T) {
	log, path := newTestLog(t)

	for range 25 {
		if err := log.Append(t.Context(), read(t, "secret.read")); err != nil {
			t.Fatalf("Append returned error: %v", err)
		}
	}

	report, err := Verify(path)
	if err != nil {
		t.Fatalf("Verify returned error: %v", err)
	}
	if report.Records != 25 {
		t.Errorf("Records = %d, want 25", report.Records)
	}
	if report.LastHash == "" {
		t.Error("the report carries no tip hash")
	}
}

func TestVerifyCatchesTampering(t *testing.T) {
	cases := map[string]func(t *testing.T, path string){
		"an altered field": func(t *testing.T, path string) {
			rewrite(t, path, func(lines []string) []string {
				lines[1] = strings.Replace(lines[1], `"tenant":"prod"`, `"tenant":"staging"`, 1)
				return lines
			})
		},
		"a removed record": func(t *testing.T, path string) {
			rewrite(t, path, func(lines []string) []string {
				return append(lines[:1], lines[2:]...)
			})
		},
		"a reordered pair": func(t *testing.T, path string) {
			rewrite(t, path, func(lines []string) []string {
				lines[0], lines[1] = lines[1], lines[0]
				return lines
			})
		},
		"an appended record": func(t *testing.T, path string) {
			rewrite(t, path, func(lines []string) []string {
				return append(lines, lines[len(lines)-1])
			})
		},
		"a truncated line": func(t *testing.T, path string) {
			rewrite(t, path, func(lines []string) []string {
				lines[1] = lines[1][:len(lines[1])/2]
				return lines
			})
		},
	}

	for name, tamper := range cases {
		t.Run(name, func(t *testing.T) {
			log, path := newTestLog(t)
			for range 4 {
				if err := log.Append(t.Context(), read(t, "secret.read")); err != nil {
					t.Fatalf("Append returned error: %v", err)
				}
			}
			if err := log.Close(); err != nil {
				t.Fatalf("Close returned error: %v", err)
			}

			tamper(t, path)

			if _, err := Verify(path); !errors.Is(err, ErrBroken) {
				t.Fatalf("Verify = %v, want ErrBroken", err)
			}
		})
	}
}

func TestEditingOneRecordBreaksEverythingAfterIt(t *testing.T) {
	log, path := newTestLog(t)
	for range 5 {
		if err := log.Append(t.Context(), read(t, "secret.read")); err != nil {
			t.Fatalf("Append returned error: %v", err)
		}
	}
	if err := log.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}

	rewrite(t, path, func(lines []string) []string {
		lines[1] = reseal(t, lines[1], func(record *Record) { record.Tenant = "staging" })
		return lines
	})

	if _, err := Verify(path); !errors.Is(err, ErrBroken) {
		t.Fatalf("Verify = %v, want ErrBroken: resealing one record must not hide it", err)
	}
}

func TestRewritingTheWholeLogIsNotDetected(t *testing.T) {
	log, path := newTestLog(t)
	for range 5 {
		if err := log.Append(t.Context(), read(t, "secret.read")); err != nil {
			t.Fatalf("Append returned error: %v", err)
		}
	}
	if err := log.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}

	rewrite(t, path, func(lines []string) []string {
		previous := Genesis
		for index, line := range lines {
			lines[index] = reseal(t, line, func(record *Record) {
				record.PrevHash = previous
				if index == 1 {
					record.Tenant = "staging"
				}
			})
			previous = hashOf(t, lines[index])
		}
		return lines
	})

	if _, err := Verify(path); err != nil {
		t.Fatalf("Verify returned %v", err)
	}
	t.Log("a chain detects partial tampering, not a rewrite by whoever can write the whole file; " +
		"only shipping records off the host or anchoring the tip elsewhere closes that")
}

func reseal(t *testing.T, line string, change func(*Record)) string {
	t.Helper()

	var record Record
	if err := json.Unmarshal([]byte(line), &record); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	change(&record)
	record.Hash = record.chain()

	encoded, err := json.Marshal(record)
	if err != nil {
		t.Fatalf("encoding: %v", err)
	}
	return string(encoded)
}

func hashOf(t *testing.T, line string) string {
	t.Helper()

	var record Record
	if err := json.Unmarshal([]byte(line), &record); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	return record.Hash
}

func TestReopeningContinuesTheChain(t *testing.T) {
	log, path := newTestLog(t)

	for range 3 {
		if err := log.Append(t.Context(), read(t, "secret.read")); err != nil {
			t.Fatalf("Append returned error: %v", err)
		}
	}
	if err := log.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}

	reopened, err := Open(path, Options{Now: func() time.Time { return origin }})
	if err != nil {
		t.Fatalf("reopening returned error: %v", err)
	}
	defer func() { _ = reopened.Close() }()

	if reopened.Sequence() != 3 {
		t.Fatalf("Sequence() = %d after reopening, want 3", reopened.Sequence())
	}
	if err := reopened.Append(t.Context(), read(t, "secret.read")); err != nil {
		t.Fatalf("Append after reopening returned error: %v", err)
	}

	report, err := Verify(path)
	if err != nil {
		t.Fatalf("Verify after reopening returned error: %v", err)
	}
	if report.Records != 4 {
		t.Errorf("Records = %d, want 4", report.Records)
	}
}

func TestOpeningATamperedLogFails(t *testing.T) {
	log, path := newTestLog(t)
	for range 3 {
		if err := log.Append(t.Context(), read(t, "secret.read")); err != nil {
			t.Fatalf("Append returned error: %v", err)
		}
	}
	if err := log.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}

	rewrite(t, path, func(lines []string) []string {
		return append(lines[:1], lines[2:]...)
	})

	if _, err := Open(path, Options{}); !errors.Is(err, ErrBroken) {
		t.Fatalf("Open = %v, want it to refuse a broken chain", err)
	}
}

func TestAppendRejectsAnUnusableEvent(t *testing.T) {
	log, _ := newTestLog(t)

	if err := log.Append(t.Context(), Event{Result: ResultAllow}); !errors.Is(err, ErrNoOperation) {
		t.Errorf("Append without an operation = %v, want ErrNoOperation", err)
	}
	if err := log.Append(t.Context(), Event{Operation: "secret.read"}); !errors.Is(err, ErrNoResult) {
		t.Errorf("Append without a result = %v, want ErrNoResult", err)
	}
	if err := log.Append(t.Context(), Event{Operation: "secret.read", Result: "maybe"}); !errors.Is(err, ErrNoResult) {
		t.Errorf("Append with an unknown result = %v, want ErrNoResult", err)
	}
}

func TestAppendAfterCloseIsRefused(t *testing.T) {
	log, _ := newTestLog(t)

	if err := log.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}
	if err := log.Append(t.Context(), read(t, "secret.read")); !errors.Is(err, ErrClosed) {
		t.Fatalf("Append = %v, want ErrClosed", err)
	}
	if err := log.Close(); err != nil {
		t.Errorf("a repeated Close returned error: %v", err)
	}
}

func TestConcurrentAppendsKeepTheChainIntact(t *testing.T) {
	log, path := newTestLog(t)

	var group sync.WaitGroup
	for worker := range 8 {
		group.Add(1)
		go func() {
			defer group.Done()
			for range 20 {
				if err := log.Append(t.Context(), read(t, "secret.read")); err != nil {
					t.Errorf("worker %d: Append returned error: %v", worker, err)
					return
				}
			}
		}()
	}
	group.Wait()

	if err := log.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}

	report, err := Verify(path)
	if err != nil {
		t.Fatalf("Verify returned error: %v", err)
	}
	if report.Records != 160 {
		t.Errorf("Records = %d, want 160", report.Records)
	}
}

func TestTheLogFileIsNotWorldReadable(t *testing.T) {
	_, path := newTestLog(t)

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != filePerm {
		t.Errorf("mode = %o, want %o", perm, filePerm)
	}

	dir, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatalf("stat on the directory: %v", err)
	}
	if perm := dir.Mode().Perm(); perm != dirPerm {
		t.Errorf("directory mode = %o, want %o", perm, dirPerm)
	}
}

func TestOpenRejectsAnEmptyPath(t *testing.T) {
	if _, err := Open("", Options{}); !errors.Is(err, ErrEmptyPath) {
		t.Fatalf("Open = %v, want ErrEmptyPath", err)
	}
	if _, err := Verify(""); !errors.Is(err, ErrEmptyPath) {
		t.Fatalf("Verify = %v, want ErrEmptyPath", err)
	}
}

func rewrite(t *testing.T, path string, change func([]string) []string) {
	t.Helper()

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading the log: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")

	if err := os.WriteFile(path, []byte(strings.Join(change(lines), "\n")+"\n"), filePerm); err != nil {
		t.Fatalf("writing the log: %v", err)
	}
}
