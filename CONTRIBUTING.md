# Contributing

## Before anything else

Security problems do not go in issues. See [SECURITY.md](SECURITY.md).

## Getting set up

```sh
git clone git@github.com:MarStack-Labs/marstack-secrets.git
cd marstack-secrets
make hooks
make check
```

`make hooks` installs a pre-commit hook that runs `make check`. GitHub Actions is disabled on this
repository to keep runner usage at zero, so that hook is where the gates actually run. Skipping it
means nothing is checked until someone else notices.

`make check` needs `gitleaks` on `PATH`. On macOS it also needs `MARSEC_ALLOW_UNPROTECTED_MEMORY=true`
to run the server, because the process protections are Linux-only; `make vm-up` gives you a Linux VM
where they work.

## What the gates are

| Gate | Fails when |
|---|---|
| `make fmt-check` | A file is not `gofmt -s` clean |
| `make vet` | `go vet` has anything to say |
| `make arch-check` | A module imports another module, or the server imports its own client |
| `make test-race` | Any test fails, including under the race detector |
| `make drill` | A snapshot cannot be saved, verified and restored |
| `make security` | `govulncheck` or `gitleaks` finds something |

## House rules

These are not style preferences; each one exists because of a specific failure.

**No comments in any file.** Not in Go, not in YAML, not in the `Makefile`, not in shell. No doc
comments, no banner separators, no `TODO`. Anything worth explaining goes in `docs/` or an ADR, where
it can be found and kept current. A comment next to code rots silently; a document that contradicts
the code is a bug someone will report.

**A module never imports another module.** Read [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) before
adding one. When two modules need each other, the consumer declares an interface and the composition
root satisfies it. `make arch-check` enforces this, and it is the rule that makes the rest work.

**Build what the current milestone needs.** [docs/ENGINEERING-PRINCIPLES.md](docs/ENGINEERING-PRINCIPLES.md)
carries a table of things deliberately not built and what will bring each one in. Adding to that
table is a normal outcome of a change; quietly building ahead of it is not.

**A dependency needs an ADR.** There is one direct dependency. Adding a second means writing down what
the standard library could not do, and what would make you remove it again.

**New security behaviour arrives with the test that asserts it.** Preferably one you have seen fail:
break the control, watch the test go red, put it back. A test that passes in both states is worse than
no test, because it reads as coverage.

## Writing tests

Name the behaviour, not the function: `TestARefusedRecordRefusesTheRequestAndSealsTheStore`, not
`TestAppend`. When the test fails months from now, the name is the bug report.

Test through the public surface with `httptest` and `t.TempDir()`. Nothing spawns a process or binds a
fixed port; reserve `:0` and read the address back.

For anything security-shaped, prefer the test that tries to get away with it. The valuable tests in
this repository are the ones that move a ciphertext to another path, replay an assertion, race sixteen
goroutines at a single-use token, or rewrite an audit log and check the chain notices.

## Commits

One small task per commit, pushed when it is done. Not one large commit at the end.

The message explains why, not what. The diff already says what. If a test caught the problem, say so —
several messages in this history record a design flaw a test found, and those are the useful ones to
read later.

No AI attribution in commit messages, and no `Co-Authored-By` trailers for tools.

Everything is in English: code, identifiers, documents, commit messages.

## Documentation

A change that alters behaviour updates the document that describes it, in the same commit. There is a
commit in this history whose whole purpose was fixing documents that had started lying after CI was
turned off, and one that fixed a README table which had silently lost rows. Both were avoidable.
