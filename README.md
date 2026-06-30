# greentic-update

Foundation library for the **Greentic update platform** — a secure, pull-based
update mechanism for both internet-connected and airgapped Greentic
environments.

This crate is the transport-agnostic core, consumed by:

- **`greentic-deployer`** (the operator CLI) for the `op get-updates` /
  `op apply-updates` verbs;
- the **Public Updater Bridge** binary, for airgapped transfer onto removable
  media;
- the **cloud Update Planner** (greentic-biz), which builds and signs update
  plans.

## Design principles

- **Deterministic and signed by default.** An update plan is a DSSE-signed
  in-toto `Statement`; every artifact is content-addressed and digest-verified.
  Verification is fail-closed against a per-environment trust root.
- **No parallel apply engine.** A plan's `target` is a `greentic.env-manifest.v1`
  document (carried here as opaque JSON); applying an update drives the existing
  `env_apply` pipeline and revision lifecycle in `greentic-deployer`.
- **Lean dependencies.** This crate does **not** depend on
  `greentic-deploy-spec`. Callers project their domain types into the
  lightweight artifact view defined here. The only workspace dependency is
  `greentic-distributor-client`, reused for DSSE/in-toto signing and the
  content-addressed download client.

## Modules

| Module      | Purpose                                                          | Phase |
|-------------|-----------------------------------------------------------------|-------|
| `plan`      | Signed `greentic.update-plan.v1` build/verify                   | P0a   |
| `catalogue` | Installed-artifact view + diff against a plan's artifacts        | P0c   |
| `staging`   | On-disk `{downloading,inbox,staged,applying,…}` state machine    | P2    |
| `envelope`  | Airgap update-bundle wrapper + import scanner                    | P5    |
| `binswap`   | Verified on-disk binary swap + rollback (binary self-update)     | P7    |

> Status: foundation skeleton. Phase 0 (P0a/P0c) is under active development.

## Build & test

```bash
cargo build
cargo test
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --all --check
# or the full local gate:
bash ci/local_check.sh
```

## License

MIT
