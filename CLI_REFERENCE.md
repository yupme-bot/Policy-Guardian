# CLI Reference (Policy Guardian v1.0)

Note: flags must come before positional arguments.

## policyguardian

- `policyguardian --version`

## policyguardian policylock snapshot

Inputs (choose one):
- `policyguardian policylock snapshot <file>`
- `policyguardian policylock snapshot --url <url>`
- `policyguardian policylock snapshot --stdin`

Flags:
- `--out <zip>` (default: `policy_snapshot.zip`)
- `--created-at <YYYY-MM-DDTHH:MM:SSZ>` (optional)
- `--max-bytes <n>` (URL only; 0 means “no limit”)

## policyguardian policylock verify

Prints `VALID` or `INVALID` and optional `reason:`.

Exit codes:
- `0` VALID
- `2` INVALID
- `4` INPUT ERROR

## policyguardian policylock show

Prints a summary of the snapshot pack.

## policyguardian consent record

```text
policyguardian consent record --subject <id> --tenant-salt <hex> --pepper <hex> [--sign-privkey <hex>] [--out <consent.json>] <snapshot.zip|snapshot_id>
```

`--sign-privkey` expects a **64-byte** Ed25519 private key (128 hex chars).

## policyguardian consent verify

```text
policyguardian consent verify <consent.json> [--resolve-snapshot]
```

Prints `VALID`, `INVALID`, or `PARTIAL`.

Exit codes:
- `0` VALID
- `1` PARTIAL
- `2` INVALID
- `4` INPUT ERROR
