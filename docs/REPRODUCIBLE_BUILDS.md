# Reproducible builds

Why: a security design is only as good as the binary actually running. Reproducible
builds let anyone rebuild a given commit and confirm — by hash — that the operator's
`sona-relay` (or a distributed client binary) is exactly the audited source, with
nothing added. "Trust the source, not the download."

## What is pinned

| Input | Where | Pin |
|---|---|---|
| Compiler | `rust-toolchain.toml` | exact version (e.g. `1.96.0`), never `stable` |
| Dependencies | `Cargo.lock` (committed) + `--locked` in the container build | exact versions + checksums |
| Build environment | `deploy/Dockerfile` | `rust:<exact>-slim-trixie`, sources at fixed `/src` |
| Host-path leakage | `RUSTFLAGS --remap-path-prefix` (Dockerfile) + `strip = "symbols"` (release profile) | no builder-specific paths in the binary |

The unit of reproducibility is the **binary**, not the Docker image (image layers embed
timestamps and will always differ). Verification therefore compares the binaries inside
two independently built images.

## Verify

```sh
./deploy/verify-reproducible.sh
```

Builds the image twice with `--no-cache`, extracts `sona-relay` + `sona-auditor` from
each, compares SHA-256. Exit 0 = bit-identical. To verify a *server operator*, build
their announced commit yourself and compare your hash against the one they publish
(`sha256sum /usr/local/bin/sona-relay` in their container).

## Rules for maintainers

* **Never** bump `rust-toolchain.toml` casually — it changes every binary hash. Own
  commit, called out in the message.
* `Cargo.lock` changes likewise change hashes; that's expected and fine — hashes are
  per-commit, not forever.
* Anything that injects build-time data (timestamps, `env!()` of host variables, build
  scripts reading the environment) breaks reproducibility. Don't.

## Known limits (honest list)

* Reproducibility is guaranteed **via the container path** (fixed toolchain, paths,
  libc). A bare `cargo build --release` on two different machines may differ (different
  host paths outside the remap, different linkers).
* The Docker *image* hash is not reproducible, only the binaries in it.
* Client binaries (Tauri desktop/Android) are not yet covered — they bundle a webview
  shell and platform signing; that work lands with the GUI phase.
