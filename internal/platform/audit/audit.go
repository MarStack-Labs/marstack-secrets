package audit

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"time"
)

const (
	ResultAllow = "allow"
	ResultDeny  = "deny"
	ResultError = "error"

	Genesis = ""
)

var (
	ErrNoOperation = errors.New("audit: an operation is required")
	ErrNoResult    = errors.New("audit: an unknown result")
	ErrClosed      = errors.New("audit: the log is closed")
	ErrBroken      = errors.New("audit: the chain does not verify")
	ErrEmptyPath   = errors.New("audit: a log path is required")
)

var results = map[string]struct{}{
	ResultAllow: {},
	ResultDeny:  {},
	ResultError: {},
}

type Event struct {
	Operation string
	Identity  string
	Tenant    string
	Path      string
	Version   int
	Result    string
	Policy    string
	Rule      string
	RequestID string
	SourceIP  string
}

func (e Event) validate() error {
	if e.Operation == "" {
		return ErrNoOperation
	}
	if _, known := results[e.Result]; !known {
		return ErrNoResult
	}
	return nil
}

type Record struct {
	Sequence  int64  `json:"seq"`
	Time      string `json:"ts"`
	Operation string `json:"op"`
	Identity  string `json:"identity,omitempty"`
	Tenant    string `json:"tenant,omitempty"`
	Path      string `json:"path,omitempty"`
	Version   int    `json:"version,omitempty"`
	Result    string `json:"result"`
	Policy    string `json:"policy,omitempty"`
	Rule      string `json:"rule,omitempty"`
	RequestID string `json:"request_id,omitempty"`
	SourceIP  string `json:"source_ip,omitempty"`
	PrevHash  string `json:"prev_hash"`
	Hash      string `json:"hash"`
}

func newRecord(sequence int64, at time.Time, event Event, previous string) Record {
	record := Record{
		Sequence:  sequence,
		Time:      at.UTC().Format(time.RFC3339Nano),
		Operation: event.Operation,
		Identity:  event.Identity,
		Tenant:    event.Tenant,
		Path:      event.Path,
		Version:   event.Version,
		Result:    event.Result,
		Policy:    event.Policy,
		Rule:      event.Rule,
		RequestID: event.RequestID,
		SourceIP:  event.SourceIP,
		PrevHash:  previous,
	}
	record.Hash = record.chain()
	return record
}

func (r Record) chain() string {
	digest := sha256.New()
	digest.Write([]byte(r.PrevHash))

	for _, field := range []string{
		strconv.FormatInt(r.Sequence, 10),
		r.Time,
		r.Operation,
		r.Identity,
		r.Tenant,
		r.Path,
		strconv.Itoa(r.Version),
		r.Result,
		r.Policy,
		r.Rule,
		r.RequestID,
		r.SourceIP,
	} {
		length := make([]byte, 4)
		binary.BigEndian.PutUint32(length, uint32(len(field)))
		digest.Write(length)
		digest.Write([]byte(field))
	}

	return hex.EncodeToString(digest.Sum(nil))
}

func (r Record) encode() ([]byte, error) {
	encoded, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	return append(encoded, '\n'), nil
}
