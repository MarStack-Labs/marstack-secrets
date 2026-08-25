package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/marstack-labs/marstack-secrets/internal/client"
	"github.com/marstack-labs/marstack-secrets/internal/platform/crypto"
)

const (
	defaultAddress = "https://127.0.0.1:8200"
	tokenFilePerm  = 0o600
	tokenDirPerm   = 0o700
)

var errUsage = errors.New("usage")

type connection struct {
	address    string
	caCertFile string
	plainHTTP  bool
	tokenFile  string
}

func (c *connection) bind(flags *flag.FlagSet) {
	flags.StringVar(&c.address, "address", envOr("MARSEC_ADDRESS", defaultAddress), "store address")
	flags.StringVar(&c.caCertFile, "ca-cert", os.Getenv("MARSEC_CACERT"), "certificate authority for the store")
	flags.BoolVar(&c.plainHTTP, "allow-plain-http", false, "talk plaintext HTTP; local development only")
	flags.StringVar(&c.tokenFile, "token-file", envOr("MARSEC_TOKEN_FILE", defaultTokenFile()), "where the session token is kept")
}

func (c *connection) open(withToken bool) (*client.Client, error) {
	made, err := client.New(client.Options{
		Address:        c.address,
		CACertFile:     c.caCertFile,
		AllowPlainHTTP: c.plainHTTP,
	})
	if err != nil {
		return nil, err
	}
	if !withToken {
		return made, nil
	}

	token, err := c.readToken()
	if err != nil {
		return nil, err
	}
	made.SetToken(token)
	return made, nil
}

func (c *connection) readToken() (crypto.Sensitive, error) {
	if fromEnv := strings.TrimSpace(os.Getenv("MARSEC_TOKEN")); fromEnv != "" {
		return crypto.Sensitive(fromEnv), nil
	}

	raw, err := os.ReadFile(c.tokenFile)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("no session token; run marsec login first")
		}
		return nil, err
	}
	return crypto.Sensitive(strings.TrimSpace(string(raw))), nil
}

func (c *connection) writeToken(token crypto.Sensitive) error {
	if err := os.MkdirAll(filepath.Dir(c.tokenFile), tokenDirPerm); err != nil {
		return err
	}
	return os.WriteFile(c.tokenFile, append([]byte(token), '\n'), tokenFilePerm)
}

func runLogin(ctx context.Context, out io.Writer, args []string) error {
	flags := flag.NewFlagSet("login", flag.ContinueOnError)
	flags.SetOutput(out)

	var link connection
	link.bind(flags)
	bootstrapFile := flags.String("bootstrap-file", "", "file holding a bootstrap token, or - for stdin")
	assertionFile := flags.String("assertion-file", "", "file holding a control plane assertion, or - for stdin")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if (*bootstrapFile == "") == (*assertionFile == "") {
		return errors.New("usage: marsec login --bootstrap-file <path>|- , or --assertion-file <path>|-")
	}

	made, err := link.open(false)
	if err != nil {
		return err
	}

	var session client.Session
	if *bootstrapFile != "" {
		credential, err := readCredential(*bootstrapFile)
		if err != nil {
			return err
		}
		defer credential.Zero()
		session, err = made.LoginBootstrap(ctx, credential)
		if err != nil {
			return err
		}
	} else {
		assertion, err := readCredential(*assertionFile)
		if err != nil {
			return err
		}
		defer assertion.Zero()
		session, err = made.LoginInstance(ctx, assertion)
		if err != nil {
			return err
		}
	}

	if err := link.writeToken(session.Token); err != nil {
		return err
	}
	fmt.Fprintf(out, "logged in; token kept in %s, expires %s\n",
		link.tokenFile, session.ExpiresAt.Format("2006-01-02T15:04:05Z07:00"))
	return nil
}

func runSecret(ctx context.Context, out io.Writer, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: marsec secret get|put|delete <tenant>/<path>")
	}

	switch args[0] {
	case "get":
		return runSecretGet(ctx, out, args[1:])
	case "put":
		return runSecretPut(ctx, out, args[1:])
	case "delete":
		return runSecretDelete(ctx, out, args[1:])
	default:
		return fmt.Errorf("unknown secret subcommand %q", args[0])
	}
}

func runSecretGet(ctx context.Context, out io.Writer, args []string) error {
	location, rest, err := positional(args, "marsec secret get <tenant>/<path> [--version N]")
	if err != nil {
		return err
	}

	flags := flag.NewFlagSet("secret get", flag.ContinueOnError)
	flags.SetOutput(out)
	var link connection
	link.bind(flags)
	version := flags.Int("version", 0, "version to read; the current one by default")
	if err := flags.Parse(rest); err != nil {
		return err
	}

	tenant, path, err := split(location)
	if err != nil {
		return err
	}

	made, err := link.open(true)
	if err != nil {
		return err
	}
	defer made.Forget()

	found, err := made.ReadSecret(ctx, tenant, path, *version)
	if err != nil {
		return err
	}
	defer found.Value.Zero()

	fmt.Fprintln(out, string(found.Value))
	return nil
}

func runSecretPut(ctx context.Context, out io.Writer, args []string) error {
	location, rest, err := positional(args, "marsec secret put <tenant>/<path> [--value v] [--cas N]")
	if err != nil {
		return err
	}

	flags := flag.NewFlagSet("secret put", flag.ContinueOnError)
	flags.SetOutput(out)
	var link connection
	link.bind(flags)
	value := flags.String("value", "", "the value; read from stdin when absent")
	cas := flags.Int("cas", -1, "expected current version; -1 to write unconditionally")
	if err := flags.Parse(rest); err != nil {
		return err
	}

	tenant, path, err := split(location)
	if err != nil {
		return err
	}

	secret, err := valueFrom(*value)
	if err != nil {
		return err
	}
	defer secret.Zero()

	made, err := link.open(true)
	if err != nil {
		return err
	}
	defer made.Forget()

	var expectation *int
	if *cas >= 0 {
		expectation = cas
	}

	version, err := made.WriteSecret(ctx, tenant, path, secret, expectation)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "wrote version %d\n", version)
	return nil
}

func runSecretDelete(ctx context.Context, out io.Writer, args []string) error {
	location, rest, err := positional(args, "marsec secret delete <tenant>/<path>")
	if err != nil {
		return err
	}

	flags := flag.NewFlagSet("secret delete", flag.ContinueOnError)
	flags.SetOutput(out)
	var link connection
	link.bind(flags)
	if err := flags.Parse(rest); err != nil {
		return err
	}

	tenant, path, err := split(location)
	if err != nil {
		return err
	}

	made, err := link.open(true)
	if err != nil {
		return err
	}
	defer made.Forget()

	if err := made.DeleteSecret(ctx, tenant, path); err != nil {
		return err
	}
	fmt.Fprintln(out, "deleted")
	return nil
}

func runParam(ctx context.Context, out io.Writer, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: marsec param get|put <tenant>/<path>")
	}

	switch args[0] {
	case "get":
		return runParamGet(ctx, out, args[1:])
	case "put":
		return runParamPut(ctx, out, args[1:])
	default:
		return fmt.Errorf("unknown param subcommand %q", args[0])
	}
}

func runParamGet(ctx context.Context, out io.Writer, args []string) error {
	location, rest, err := positional(args, "marsec param get <tenant>/<path>")
	if err != nil {
		return err
	}

	flags := flag.NewFlagSet("param get", flag.ContinueOnError)
	flags.SetOutput(out)
	var link connection
	link.bind(flags)
	verbose := flags.Bool("verbose", false, "report where the value came from")
	if err := flags.Parse(rest); err != nil {
		return err
	}

	tenant, path, err := split(location)
	if err != nil {
		return err
	}

	made, err := link.open(true)
	if err != nil {
		return err
	}
	defer made.Forget()

	found, err := made.ReadParameter(ctx, tenant, path)
	if err != nil {
		return err
	}
	defer found.Value.Zero()

	if *verbose {
		fmt.Fprintf(out, "kind      %s\nfrom      %s\ninherited %t\nsensitive %t\n",
			found.Kind, found.ResolvedFrom, found.Inherited, found.Sensitive)
		if len(found.References) > 0 {
			fmt.Fprintf(out, "refers to %s\n", strings.Join(found.References, " "))
		}
	}
	fmt.Fprintln(out, string(found.Value))
	return nil
}

func runParamPut(ctx context.Context, out io.Writer, args []string) error {
	location, rest, err := positional(args, "marsec param put <tenant>/<path> --kind <kind> [--value v]")
	if err != nil {
		return err
	}

	flags := flag.NewFlagSet("param put", flag.ContinueOnError)
	flags.SetOutput(out)
	var link connection
	link.bind(flags)
	kind := flags.String("kind", "string", "string, int, bool or stringlist")
	value := flags.String("value", "", "the value; read from stdin when absent")
	if err := flags.Parse(rest); err != nil {
		return err
	}

	tenant, path, err := split(location)
	if err != nil {
		return err
	}

	parameter, err := valueFrom(*value)
	if err != nil {
		return err
	}
	defer parameter.Zero()

	made, err := link.open(true)
	if err != nil {
		return err
	}
	defer made.Forget()

	if err := made.WriteParameter(ctx, tenant, path, *kind, parameter); err != nil {
		return err
	}
	fmt.Fprintln(out, "written")
	return nil
}

func runStatus(ctx context.Context, out io.Writer, args []string) error {
	flags := flag.NewFlagSet("status", flag.ContinueOnError)
	flags.SetOutput(out)
	var link connection
	link.bind(flags)
	if err := flags.Parse(args); err != nil {
		return err
	}

	made, err := link.open(false)
	if err != nil {
		return err
	}

	status, err := made.SealStatus(ctx)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "state     %s\nshares    %d\nthreshold %d\nprogress  %d\n",
		status.State, status.Shares, status.Threshold, status.Progress)
	return nil
}

func valueFrom(inline string) (crypto.Sensitive, error) {
	if inline != "" {
		fmt.Fprintln(os.Stderr,
			"warning: --value puts the value in this process's arguments, where other users can read it; prefer stdin")
		return crypto.Sensitive(inline), nil
	}

	raw, err := io.ReadAll(io.LimitReader(os.Stdin, 1<<20))
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 {
		return nil, errors.New("no value given: pass --value or pipe it on stdin")
	}
	return crypto.Sensitive(strings.TrimRight(string(raw), "\n")), nil
}

func readCredential(source string) (crypto.Sensitive, error) {
	if source == "-" {
		raw, err := io.ReadAll(io.LimitReader(os.Stdin, 1<<20))
		if err != nil {
			return nil, err
		}
		return crypto.Sensitive(strings.TrimSpace(string(raw))), nil
	}

	raw, err := os.ReadFile(source)
	if err != nil {
		return nil, err
	}
	return crypto.Sensitive(strings.TrimSpace(string(raw))), nil
}

func split(location string) (string, string, error) {
	tenant, path, found := strings.Cut(location, "/")
	if !found || tenant == "" || path == "" {
		return "", "", fmt.Errorf("%q should be <tenant>/<path>", location)
	}
	return tenant, path, nil
}

func envOr(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func defaultTokenFile() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(os.TempDir(), "marsec-token")
	}
	return filepath.Join(home, ".marsec", "token")
}
