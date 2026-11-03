# mTLS for the Controller ↔ Node gRPC Link

> العربية: [docs/MTLS.ar.md](MTLS.ar.md)


This document covers the mutual-TLS transport added in Pillar 1 of the
enterprise-hardening plan. It replaces the plaintext gRPC channel and the
`node_id`-from-message identity model described in the README's
"Known Limitations".

## Threat model addressed

Before this change the Controller accepted statistics by the `node_id`
written inside each message, after one successful handshake. Consequences:

| Attack | Before | After |
|---|---|---|
| Passive sniffing of traffic telemetry | Possible | Prevented (TLS 1.3) |
| On-path modification / MITM | Possible | Prevented (cert pinning to CA) |
| Impersonation of another node after winning one handshake | Possible | Prevented (identity comes from cert URI SAN) |
| Rogue node injecting forged stats | Possible with a stolen API key | Requires a CA-signed identity cert |

## Identity model

Each Node certificate carries a URI SAN:

```
spiffe://xsight/node/<node_id>
```

The Controller derives the node identity **from the verified certificate**,
never from the `NodeHandshake.node_id` field. The two must match; a mismatch
is rejected before any statistics are processed.

## Files on disk

| Role | Files |
|---|---|
| CA (offline / secured) | `ca.crt`, `ca.key` |
| Controller | `controller.crt`, `controller.key`, `ca.crt` |
| Node `<id>` | `<id>.crt`, `<id>.key`, `ca.crt` |

Private keys must be mode `0600` and owned by the service user. The CA key
should live offline or in an HSM; it is only needed to issue/rotate leaves.

## Generating material

A helper is provided (`cmd/xsight-cert`). It is bundled in the Controller image at
`/usr/local/bin/xsight-cert`, so no host Go toolchain is needed — run it through the
container, where `/etc/xsight/pki` is the mounted `./pki` directory:

```bash
# 0. Optional: build from source instead of using the image
(cd controller && go build -o /usr/local/bin/xsight-cert ./cmd/xsight-cert)

# From the repository root, prefix every command below with:
alias xsight-cert='docker compose exec controller xsight-cert'
```

Typical flow:

```bash
# 1. Create the deployment CA (once, keep ca.key offline afterwards)
xsight-cert init-ca --out /etc/xsight/pki --cn "xSight Deployment CA"

# 2. Issue the Controller certificate
xsight-cert issue --ca /etc/xsight/pki --cn controller \
  --dns controller --dns localhost --ip 10.0.0.10 \
  --out /etc/xsight/pki/controller

# 3. Issue one certificate per Node
xsight-cert issue --ca /etc/xsight/pki --node-id node-01 \
  --out /etc/xsight/pki/node-01

# 4. Verify a chain before deploying
xsight-cert verify --ca /etc/xsight/pki/ca.crt \
  --cert /etc/xsight/pki/node-01.crt --node-id node-01
```

The helper is baked into the image, but the Compose volume mount is **read-only** for the
running Controller (it only ever needs to read `ca.crt` / `*.crt` / `*.key`). Generate material
with a one-off container that mounts `./pki` read-write:

```bash
mkdir -p pki
docker compose run --rm -v "$PWD/pki:/etc/xsight/pki" --entrypoint xsight-cert \
  controller init-ca --out /etc/xsight/pki --cn "xSight Deployment CA"
# repeat with: issue --ca /etc/xsight/pki --cn controller ...   and   --node-id <id>
```

The image runs as UID 10001, so have that UID own the directory the Controller must read
(`sudo chown -R 10001:10001 pki && chmod 700 pki`, `chmod 600 pki/*.key`) before starting the
service. Keep `ca.key` offline afterwards.

## Controller configuration

```yaml
tls:
  enabled: true
  ca_file: /etc/xsight/pki/ca.crt      # verifies NODE client certificates
  cert_file: /etc/xsight/pki/controller.crt
  key_file: /etc/xsight/pki/controller.key
  server_name: controller              # expected name in our own leaf
  allow_legacy_tls12: false            # keep false unless a middlebox forces it
```

## Node configuration

```yaml
tls:
  enabled: true
  ca_file: /etc/xsight/pki/ca.crt      # verifies the CONTROLLER certificate
  cert_file: /etc/xsight/pki/node-01.crt
  key_file: /etc/xsight/pki/node-01.key
  server_name: controller              # must match a SAN in controller.crt
```

## Rollout sequence (zero-downtime migration)

1. Deploy the CA and issue the Controller certificate; set `tls.enabled: true`
   on the Controller but keep `tls.enabled: false` on all Nodes for now.
   *The Controller now requires client certs, so this would break plaintext
   nodes.* Therefore use the order below instead:
2. **Stage A** — leave the Controller plaintext. Issue all node certificates
   and roll them out with `tls.enabled: false` (certs on disk, unused).
3. **Stage B** — flip the Controller to `tls.enabled: true` during a
   maintenance window. All Nodes must already carry certs and be flipped at
   the same time (the listener no longer accepts plaintext).
4. **Stage C** — verify every node shows `handshake accepted` with
   `tls: ... (mTLS)` in the Controller log.

> If a staged cut-over is impossible, enable TLS on all Nodes and the
> Controller in the same change window. The Controller rejects plaintext as
> soon as `tls.enabled` is true.

## Rotation

The Node and Controller reload their leaf certificate from disk when the
file's mtime or size changes, checked at most every 30 seconds per handshake.
To rotate:

1. Issue a new leaf with the same `node_id` / server name.
2. Atomically replace `cert_file` and `key_file` (write to a temp file in the
   same directory, then `mv`).
3. The next reconnect uses the new material; no restart required.

Rotating the **CA** requires a trust bundle containing both old and new CA
certificates during the overlap, then a second pass to drop the old one.

## Revocation

Certificate revocation is not implemented (no CRL/OCSP). To remove a node:

1. Disable the node in the Web UI (`enabled: false`) — the handshake is
   rejected regardless of certificate validity.
2. Delete its certificate files and re-issue only if it returns.

Disabling in the UI is the authoritative control; certificates are not a
substitute for it.

## Failure modes

| Symptom | Cause |
|---|---|
| `tls: load keypair` at startup | Missing/unreadable cert or key file |
| `tls: CA ... contains no PEM certificate` | Wrong `ca_file` format |
| Node: `certificate has no spiffe://xsight/node/<id> URI SAN` | Leaf issued without `--node-id` |
| Node: `x509: certificate signed by unknown authority` | Node `ca_file` is not the CA that signed the Controller leaf |
| Node: `x509: certificate is valid for X, not Y` | `server_name` does not match a SAN in the Controller leaf |
| Handshake rejected `identity mismatch` | Cert SAN node id differs from configured `node_id` |
