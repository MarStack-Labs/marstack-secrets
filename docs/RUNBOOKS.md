
# Runbooks

Each of these is written to be followed under pressure, by someone who did not write the code. Read
the whole procedure before starting any of it.

## Restarting the store

The store boots sealed. Nothing is served until a quorum of Shamir shares is presented, so a restart
is an outage until people show up.

```sh
systemctl restart marstack-secrets
marsec status
```

Then, from each share holder in turn:

```sh
curl -s -X POST https://secrets.internal:8200/v1/sys/unseal -d '{"share":"<share>"}'
```

`progress` counts shares accepted so far. A wrong quorum discards every collected share and starts
again from zero, so a mistake costs a round rather than corrupting anything.

## A secret has leaked

Rotating the value is necessary and not sufficient: every identity that already read it still holds a
copy, and no amount of bookkeeping takes that back. What can be done is stop those identities from
reading anything further, which forces re-authentication that a live workload performs by itself and a
stolen token cannot.

```sh
marsec secret get prod/apps/payment/db > /dev/null    # confirm the path
printf '<new value>' | marsec secret put prod/apps/payment/db --cas <current version>
```

Then revoke every holding under the affected prefix, which also revokes the holders' tokens:

```sh
curl -s -X PUT https://secrets.internal:8200/v1/sys/leases/revoke-prefix \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"prefix":"secret/prod/apps/payment/"}'
{"leases":3,"identities":["instance/web-01","instance/web-02"],"tokens":4}
```

The response names every identity that held a copy. That list is the incident's blast radius; write it
down before doing anything else.

Note that the caller's own token goes too if it held a lease under that prefix. That is intended. Log
in again.

Finally, read the trail for what happened before the rotation:

```sh
grep 'secret/prod/apps/payment' /var/log/marstack-secrets/audit.log | jq -c '{ts,identity,op,version,result}'
```

The `version` field matters more than the timestamp: it says which value each identity received.

## An identity is compromised

```sh
marsec operator identity disable instance/web-01
disabled instance/web-01 and revoked 2 token(s)
```

Disabling is permanent for that name. A destroyed and rebuilt instance authenticating with the same
identity will be refused, which is deliberate: the name is compromised, not just the credential.

## The store has sealed itself

The store seals when the audit sink fails, because access that cannot be recorded is not access this
store will serve. Find out why before unsealing, or it will seal again on the first request.

```sh
journalctl -u marstack-secrets | grep 'audit sink'
df -h /var/log/marstack-secrets
marsec operator audit verify
```

Three causes, in order of likelihood: the disk holding the audit log is full; the log was tampered
with or truncated; the filesystem went read only.

For a full disk, archive the log rather than deleting it, then let the store continue on a new file:

```sh
systemctl stop marstack-secrets
mv /var/log/marstack-secrets/audit.log /archive/audit-$(date -u +%Y%m%dT%H%M%SZ).log
systemctl start marstack-secrets
```

The new log starts a fresh chain from sequence one. Keep the archived file: the chain that verifies
across a rotation boundary is the pair of files, not either one alone.

For a chain that does not verify, do not rotate it away. `marsec operator audit verify` names the
record where it broke; preserve the file and treat it as evidence.

## Break-glass: no session token and nobody logged in

Provisioning does not need the network or an unsealed store. On the host, as root:

```sh
sudo -u marstack-secrets marsec operator identity add service/breakglass --tenant prod --kind bootstrap
sudo -u marstack-secrets marsec operator policy put breakglass --tenant prod --rules /tmp/rules.json
sudo -u marstack-secrets marsec operator policy bind service/breakglass --tenant prod --policy breakglass
sudo -u marstack-secrets marsec operator bootstrap service/breakglass --ttl 5m
```

The bootstrap token is single use and short lived. Exchange it immediately:

```sh
marsec login --bootstrap-file /run/breakglass-token
```

Remove the identity afterwards. Local root is inside the trust boundary by design, which is exactly
why this path works and exactly why it should leave a trail: every step above is in the audit log.

## Restore from a snapshot

A snapshot holds encrypted data and no root key, so a leaked snapshot is not leaked secrets. It is
also useless without a quorum of shares, which is the same property stated from the other side.

```sh
systemctl stop marstack-secrets
mv /var/lib/marstack-secrets/marsec.db /var/lib/marstack-secrets/marsec.db.aside
marsec operator snapshot verify /backup/marsec-20260825.snap
marsec operator snapshot restore /backup/marsec-20260825.snap --data-dir /var/lib/marstack-secrets
systemctl start marstack-secrets
```

Restore refuses to write over an existing database. Move the old one aside rather than deleting it:
until the restored store is unsealed and verified, the file you were about to delete is the only other
copy.

The restored store is sealed. Unseal it with the shares that belonged to the store the snapshot came
from; shares from a differently initialized store will be refused with `unseal_failed`.

Practise this. `make drill` runs the whole save, verify and restore cycle against a scratch store and
fails if the restored copy differs.

## Rotating a key encryption key

Not yet possible. The derivation supports versions and `crypto.Rewrap` exists to move data keys onto a
new key encryption key without touching payloads, but nothing raises the version yet. Recorded here
so the gap is known rather than discovered during an incident.
