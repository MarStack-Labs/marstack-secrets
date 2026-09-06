# ADR 0007 — A browser interface, off by default and without privilege

- Status: accepted
- Date: 2026-09-06

## Context

`docs/ROADMAP.md` deferred a web interface beyond v1, and `docs/THREAT-MODEL.md` argued that response
wrapping was unnecessary because every channel through which a value could leak was already closed:
values never appear in command arguments, the audit log has no field for them, and a consumer that can
authenticate reads directly.

A browser interface reopens that argument. It renders decrypted values onto a screen, holds a session
token inside a tab, and introduces a class of attack the store did not previously have: cross site
scripting, where injected script running in the page can read whatever the page can read.

Both comparable products ship one. Vault serves an Ember application from the Vault process, disabled
unless the operator writes `ui = true`. AWS Secrets Manager has no interface of its own; the console is
a separate service that calls the same API with the caller's credentials.

The interface was asked for after the trade was stated. This records the shape chosen so that the cost
is bounded and visible rather than absorbed.

## Decision

The interface exists, is off unless `MARSEC_UI_ENABLED` is set, and logs a warning on every boot when
it is on. That is the same shape as `MARSEC_ALLOW_INSECURE_HTTP`: a secure default with an insecure
path that is explicit and loud.

It has no privilege of its own. `internal/modules/ui` serves three embedded files and registers no API
route, holds no state, and reaches no store. The browser calls the endpoints that already exist,
carrying the operator's own session token, through the same policy checks. An identity with no policy
is refused in the page exactly as it is refused by `curl`.

No framework and no build step. This follows ADR 0002, but it also buys the security property that
matters most here: with no bundler there is no inline script or style to excuse, so the policy can be
`default-src 'none'` with `script-src 'self'` and no `unsafe-inline` anywhere.

The session token lives in a JavaScript variable and nowhere else. Not `localStorage`, not
`sessionStorage`, not a cookie. Reloading the page signs the operator out.

Values arrive masked and are revealed only when the operator asks. Copying to the clipboard is offered
and labelled, because an unlabelled clipboard write is worse than a labelled one.

The assets load while the store is sealed, since a page that could not load until the store was open
could never be used to open it. They contain no secrets, so serving them sealed reveals nothing.

## Consequences

Positive:

- An operator can unseal, read, write, inspect leases, ask what a policy permits, and rotate without
  assembling `curl` commands.
- The interface cannot become a privilege escalation path by accident, because it has no server side
  data path to escalate through. Adding one would mean adding a route to a module that currently
  serves files.
- The policy is held shut from both ends by tests: one fails if the policy loosens, another fails if
  the page grows an `onclick` or an inline style, a third fails if the script ever mentions
  `innerHTML`, and a fourth fails if it ever mentions browser storage.

Negative:

- Cross site scripting is now a threat where it was not. The policy is the mitigation, and a mitigation
  is not an absence.
- A decrypted value on a screen can be photographed, screen recorded, or seen over a shoulder. No
  control in this process addresses that.
- The clipboard is outside the process boundary entirely. Anything on the system can read it.
- Signing out on every reload is a real cost to the operator, accepted so that a stolen browser profile
  contains no token.
- `docs/THREAT-MODEL.md` can no longer claim every value bearing channel is closed. It now says so.

## Related

`docs/THREAT-MODEL.md` records what the interface adds to the boundary. `docs/CONFIGURATION.md`
records the switch.
