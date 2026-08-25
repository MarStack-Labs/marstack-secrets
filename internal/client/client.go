package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/marstack-labs/marstack-secrets/internal/platform/crypto"
)

const (
	DefaultTimeout  = 10 * time.Second
	maxResponseSize = 1 << 20
	bearerScheme    = "Bearer "
)

var (
	ErrNoAddress     = errors.New("client: an address is required")
	ErrPlaintext     = errors.New("client: refusing to talk plaintext HTTP without an explicit opt-in")
	ErrBadAddress    = errors.New("client: the address is not a usable URL")
	ErrNoToken       = errors.New("client: this call needs a token")
	ErrUnauthorized  = errors.New("client: the store refused the credential")
	ErrForbidden     = errors.New("client: the store refused the request")
	ErrNotFound      = errors.New("client: no such path")
	ErrConflict      = errors.New("client: the expected version does not match")
	ErrSealed        = errors.New("client: the store is sealed")
	ErrRateLimited   = errors.New("client: the store is rate limiting this caller")
	ErrUnavailable   = errors.New("client: the store cannot serve this request")
	ErrResponseLarge = errors.New("client: the response is larger than the accepted maximum")
)

type Options struct {
	Address        string
	CACertFile     string
	RootCAs        *x509.CertPool
	AllowPlainHTTP bool
	Timeout        time.Duration
}

type Client struct {
	base  string
	http  *http.Client
	token crypto.Sensitive
}

func New(opts Options) (*Client, error) {
	if opts.Address == "" {
		return nil, ErrNoAddress
	}

	parsed, err := url.Parse(opts.Address)
	if err != nil || parsed.Host == "" {
		return nil, ErrBadAddress
	}
	switch parsed.Scheme {
	case "https":
	case "http":
		if !opts.AllowPlainHTTP {
			return nil, ErrPlaintext
		}
	default:
		return nil, ErrBadAddress
	}

	roots := opts.RootCAs
	if roots == nil && opts.CACertFile != "" {
		pem, err := os.ReadFile(opts.CACertFile)
		if err != nil {
			return nil, err
		}
		roots = x509.NewCertPool()
		if !roots.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("client: %s holds no usable certificate", opts.CACertFile)
		}
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}

	return &Client{
		base: strings.TrimSuffix(opts.Address, "/"),
		http: &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					MinVersion: tls.VersionTLS13,
					RootCAs:    roots,
				},
				ForceAttemptHTTP2: true,
			},
		},
	}, nil
}

func (c *Client) SetToken(token crypto.Sensitive) {
	c.token = token
}

func (c *Client) Token() crypto.Sensitive {
	return c.token
}

func (c *Client) Forget() {
	c.token.Zero()
	c.token = nil
}

type request struct {
	method     string
	path       string
	query      url.Values
	body       any
	needsToken bool
}

func (c *Client) call(ctx context.Context, spec request, into any) error {
	if spec.needsToken && len(c.token) == 0 {
		return ErrNoToken
	}

	var payload io.Reader
	if spec.body != nil {
		encoded, err := json.Marshal(spec.body)
		if err != nil {
			return err
		}
		payload = bytes.NewReader(encoded)
	}

	target := c.base + spec.path
	if len(spec.query) > 0 {
		target += "?" + spec.query.Encode()
	}

	httpRequest, err := http.NewRequestWithContext(ctx, spec.method, target, payload)
	if err != nil {
		return err
	}
	if spec.body != nil {
		httpRequest.Header.Set("Content-Type", "application/json")
	}
	if len(c.token) > 0 {
		httpRequest.Header.Set("Authorization", bearerScheme+string(c.token))
	}

	response, err := c.http.Do(httpRequest)
	if err != nil {
		return err
	}
	defer func() { _ = response.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(response.Body, maxResponseSize+1))
	if err != nil {
		return err
	}
	if len(body) > maxResponseSize {
		return ErrResponseLarge
	}

	if response.StatusCode >= 400 {
		return statusError(response.StatusCode, body)
	}
	if into == nil || len(body) == 0 {
		return nil
	}
	return json.Unmarshal(body, into)
}

type problem struct {
	Error struct {
		Code string `json:"code"`
	} `json:"error"`
}

func statusError(status int, body []byte) error {
	var detail problem
	_ = json.Unmarshal(body, &detail)
	code := detail.Error.Code

	switch status {
	case http.StatusUnauthorized:
		return ErrUnauthorized
	case http.StatusForbidden:
		return ErrForbidden
	case http.StatusNotFound:
		return ErrNotFound
	case http.StatusConflict:
		return ErrConflict
	case http.StatusTooManyRequests:
		return ErrRateLimited
	case http.StatusServiceUnavailable:
		if code == "sealed" {
			return ErrSealed
		}
		return ErrUnavailable
	default:
		if code == "" {
			return fmt.Errorf("client: the store answered %d", status)
		}
		return fmt.Errorf("client: the store answered %d (%s)", status, code)
	}
}
