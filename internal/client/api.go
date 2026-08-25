package client

import (
	"context"
	"net/url"
	"strconv"
	"time"

	"github.com/marstack-labs/marstack-secrets/internal/platform/crypto"
)

type Session struct {
	Token     crypto.Sensitive
	ExpiresAt time.Time
}

type Secret struct {
	Value     crypto.Sensitive
	Version   int
	CreatedAt time.Time
	LeaseID   string
	LeaseTTL  time.Duration
}

type Parameter struct {
	Path         string
	ResolvedFrom string
	Inherited    bool
	Kind         string
	Value        crypto.Sensitive
	Sensitive    bool
	References   []string
}

type SealStatus struct {
	State     string `json:"state"`
	Shares    int    `json:"shares"`
	Threshold int    `json:"threshold"`
	Progress  int    `json:"progress"`
}

type sessionBody struct {
	Token     string `json:"token"`
	ExpiresAt string `json:"expires_at"`
}

func (c *Client) LoginBootstrap(ctx context.Context, token crypto.Sensitive) (Session, error) {
	return c.login(ctx, "/v1/auth/bootstrap/login", map[string]string{"token": string(token)})
}

func (c *Client) LoginInstance(ctx context.Context, assertion []byte) (Session, error) {
	return c.login(ctx, "/v1/auth/instance/login", map[string]string{"assertion": string(assertion)})
}

func (c *Client) login(ctx context.Context, path string, body any) (Session, error) {
	var answer sessionBody
	if err := c.call(ctx, request{method: "POST", path: path, body: body}, &answer); err != nil {
		return Session{}, err
	}

	session := Session{Token: crypto.Sensitive(answer.Token)}
	if answer.ExpiresAt != "" {
		expiry, err := time.Parse(time.RFC3339, answer.ExpiresAt)
		if err != nil {
			return Session{}, err
		}
		session.ExpiresAt = expiry
	}

	c.SetToken(session.Token)
	return session, nil
}

type secretBody struct {
	Value     string `json:"value"`
	Version   int    `json:"version"`
	CreatedAt string `json:"created_at"`
	LeaseID   string `json:"lease_id"`
	LeaseTTL  int    `json:"lease_ttl"`
}

func (c *Client) ReadSecret(ctx context.Context, tenant, path string, version int) (Secret, error) {
	query := url.Values{}
	if version > 0 {
		query.Set("version", strconv.Itoa(version))
	}

	var answer secretBody
	err := c.call(ctx, request{
		method:     "GET",
		path:       "/v1/secret/data/" + tenant + "/" + path,
		query:      query,
		needsToken: true,
	}, &answer)
	if err != nil {
		return Secret{}, err
	}

	found := Secret{
		Value:    crypto.Sensitive(answer.Value),
		Version:  answer.Version,
		LeaseID:  answer.LeaseID,
		LeaseTTL: time.Duration(answer.LeaseTTL) * time.Second,
	}
	if answer.CreatedAt != "" {
		created, err := time.Parse(time.RFC3339, answer.CreatedAt)
		if err != nil {
			return Secret{}, err
		}
		found.CreatedAt = created
	}
	return found, nil
}

type writeBody struct {
	Value string `json:"value"`
	CAS   *int   `json:"cas,omitempty"`
}

func (c *Client) WriteSecret(ctx context.Context, tenant, path string, value crypto.Sensitive, cas *int) (int, error) {
	var answer struct {
		Version int `json:"version"`
	}
	err := c.call(ctx, request{
		method:     "PUT",
		path:       "/v1/secret/data/" + tenant + "/" + path,
		body:       writeBody{Value: string(value), CAS: cas},
		needsToken: true,
	}, &answer)
	return answer.Version, err
}

func (c *Client) DeleteSecret(ctx context.Context, tenant, path string) error {
	return c.call(ctx, request{
		method:     "DELETE",
		path:       "/v1/secret/data/" + tenant + "/" + path,
		needsToken: true,
	}, nil)
}

type parameterBody struct {
	Path         string   `json:"path"`
	ResolvedFrom string   `json:"resolved_from"`
	Inherited    bool     `json:"inherited"`
	Kind         string   `json:"kind"`
	Value        string   `json:"value"`
	Sensitive    bool     `json:"sensitive"`
	References   []string `json:"references"`
}

func (c *Client) ReadParameter(ctx context.Context, tenant, path string) (Parameter, error) {
	var answer parameterBody
	err := c.call(ctx, request{
		method:     "GET",
		path:       "/v1/param/data/" + tenant + "/" + path,
		needsToken: true,
	}, &answer)
	if err != nil {
		return Parameter{}, err
	}

	return Parameter{
		Path:         answer.Path,
		ResolvedFrom: answer.ResolvedFrom,
		Inherited:    answer.Inherited,
		Kind:         answer.Kind,
		Value:        crypto.Sensitive(answer.Value),
		Sensitive:    answer.Sensitive,
		References:   answer.References,
	}, nil
}

func (c *Client) WriteParameter(ctx context.Context, tenant, path, kind string, value crypto.Sensitive) error {
	return c.call(ctx, request{
		method: "PUT",
		path:   "/v1/param/data/" + tenant + "/" + path,
		body: map[string]string{
			"kind":  kind,
			"value": string(value),
		},
		needsToken: true,
	}, nil)
}

func (c *Client) RenewLease(ctx context.Context, id string, ttl time.Duration) error {
	return c.call(ctx, request{
		method: "PUT",
		path:   "/v1/sys/leases/renew",
		body: map[string]any{
			"lease_id": id,
			"ttl":      int(ttl.Seconds()),
		},
		needsToken: true,
	}, nil)
}

func (c *Client) SealStatus(ctx context.Context) (SealStatus, error) {
	var answer SealStatus
	err := c.call(ctx, request{method: "GET", path: "/v1/sys/seal-status"}, &answer)
	return answer, err
}
