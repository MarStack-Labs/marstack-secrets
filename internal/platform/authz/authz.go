package authz

import "log/slog"

type Capability string

const (
	Read    Capability = "read"
	Write   Capability = "write"
	List    Capability = "list"
	Delete  Capability = "delete"
	Destroy Capability = "destroy"
	Deny    Capability = "deny"
)

var capabilities = map[Capability]struct{}{
	Read:    {},
	Write:   {},
	List:    {},
	Delete:  {},
	Destroy: {},
	Deny:    {},
}

func (c Capability) Valid() bool {
	_, known := capabilities[c]
	return known
}

func (c Capability) Grantable() bool {
	return c.Valid() && c != Deny
}

type Decision struct {
	Allowed bool
	Policy  string
	Rule    string
	Reason  string
}

func (d Decision) LogValue() slog.Value {
	return slog.GroupValue(
		slog.Bool("allowed", d.Allowed),
		slog.String("policy", d.Policy),
		slog.String("rule", d.Rule),
		slog.String("reason", d.Reason),
	)
}
