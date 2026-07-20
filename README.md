# Pando

Pando carries the state between your keyboard and the last push to every machine you use. Git remains history; Pando supplies presence.

Phase 0 proved the two-machine handoff. The Phase 1 implementation now has device-first onboarding with one-time enrollment codes, per-device encrypted transport, background watchers, Git-aware working-tree capture, safe first-join merging, and interactive conflict resolution. Real-machine dogfooding remains the release gate.

## Build and test

```sh
cargo test
cargo build --release
```

Run the deterministic local handoff demo:

```sh
cargo run -- demo
```

## Getting started

Pando is device-first: machines join a network once, then pick which hosted folders they carry. Build the release binary on every machine.

On the first device — ideally the always-on one — bring up a network and host a folder. Pando recursively discovers the Git repositories below the folder, assigns stable workspace IDs, and installs background services (the authority plus one watcher per repository):

```sh
pando up
pando share ~/Code --name code
```

Allow TCP port 7337 through the host firewall. To admit another machine, print a one-time code:

```sh
pando invite
```

The code is single-use, expires in 15 minutes, and dies after 3 failed attempts. On the other machine, join the network and then any hosted folder:

```sh
pando up --to HOST_IP:7337 --code xxxxx-xxxxx
pando join code            # lands in ~/Pando/code, or pass a path
```

Enrollment mints per-device credentials over an encrypted channel — nothing secret is copied between machines by hand, and `pando revoke <device>` expels a machine instantly. Existing disjoint files and subfolders are unioned on first join. If the same path differs, neither side is overwritten: Pando preserves the joining device as a pending version for an explicit decision in the TUI.

Day-to-day commands:

```sh
pando            # dashboard (same as `pando tui`)
pando folders    # folders hosted on the network
pando devices    # machines on the network
pando status     # per-folder sync state
pando sync       # one-shot push of every joined folder
```

`up`, `share`, and `join` install launchd/systemd services automatically; pass `--no-services` to skip that. The daemon watches changes, performs a full classified scan every 60 seconds, fetches Git remotes every 30 seconds, and synchronizes dirty files plus `.git` state without checking out, merging, rebasing, or pulling.

When a path changed on both devices, the TUI shows `Needs your decision`. It offers: keep the network version, keep this device, keep both copies, open the selected file in `$VISUAL`/`$EDITOR`, or publish a manual resolution. Every materializing choice asks for confirmation. The daemon remains non-interactive and never blocks waiting for terminal input.

Every TCP RPC runs inside a Noise `NNpsk0` session using ChaCha20-Poly1305. Each device holds its own transport key, minted at enrollment; wrong-key and legacy plaintext clients are rejected, and revocation deletes the device's key from the registry. A separate network key encrypts escape bundles pushed to Git remotes — a revoked device keeps that key, so it can still read escape bundles it already had access to; rotate it if that matters. The self-hosted authority is trusted and stores the synchronized data in readable form on that machine, just as the endpoint machines do. Ciphertext-only storage is required before a hosted, untrusted Pando authority.

The lower-level `serve`, `watch`, `reconcile`, `verify`, `gc`, and `restore` commands remain available (hidden from `--help`) for diagnostics and custom deployments.

## Classification

Pando syncs portable working state by default, including Git-ignored secrets such as `.env`. It excludes conservative built-in derived and machine-local paths:

- Rust `target/` at the repository root.
- `node_modules/`, Python virtual environments and caches, Gradle/Next/Turbo/Parcel caches.
- Python bytecode, `.DS_Store`, `Thumbs.db`, sockets, and other special files.

Add repository-specific rules to `.pandoignore` using Git-ignore syntax. User-wide rules use the same syntax in `~/.config/pando/ignore` (or `$PANDO_CONFIG_HOME/ignore`; `$XDG_CONFIG_HOME/pando/ignore` is also honored). Precedence is built-ins, then user-wide rules, then repository rules, so the repository can make the final override. The flattened policy is stored in each snapshot so receivers materialize it consistently. For example, `!/target/` explicitly makes the root `target/` portable. `.git/` and `.pandoignore` itself always remain portable, while the root `.pando/` directory always remains local.

Pando intentionally does not inherit `.gitignore`: Git-ignored files are often exactly the uncommitted state Pando exists to carry. Use `.pandoignore` for additional derived or local-only paths.

Explain the winning classification decision without changing anything:

```sh
pando classify node_modules --repo ~/Code/project --directory
pando classify .env --repo ~/Code/project
```

The result names the winning built-in, user-wide, or repository rule. `--directory` is useful when diagnosing a directory path that does not exist yet.

## Dependency rehydration

Pando can rebuild classified dependency trees from portable manifests and lockfiles. The Phase 1 runner recognizes root and nested projects with these exact recipes:

- `package.json` + `package-lock.json` → `npm ci`
- `package.json` + `pnpm-lock.yaml` → `pnpm install --frozen-lockfile`
- `package.json` + `yarn.lock` → `yarn install --frozen-lockfile`
- `package.json` + `bun.lock` or `bun.lockb` → `bun install --frozen-lockfile`
- `pyproject.toml` + `uv.lock` → `uv sync --frozen`
- `pyproject.toml` + `poetry.lock` → `poetry install --no-interaction`
- `Cargo.toml` + `Cargo.lock` → `cargo fetch --locked`
- `go.mod` + `go.sum` → `go mod download`

Run recipes explicitly:

```sh
pando hydrate --repo ~/Code/project
```

Or opt in to running changed recipes after the watcher applies a remote snapshot:

```sh
pando watch <workspace-id> --rehydrate
```

Workspace IDs are listed by `pando folders`; the watcher reads everything else (paths, authority address, keys) from the device configuration.

Pando invokes only these known executables directly—never through a shell—and caches successful fingerprints outside the repository. Supported lockfile recipes cover npm, pnpm, Yarn, Bun, uv, Poetry, Cargo, and Go. Successful `node_modules` and virtual-environment outputs are archived into a per-platform local artifact CAS; archives are keyed by their BLAKE3 content hash and re-verified before restoration. If a matching derived tree is missing, Pando restores it from cache before running the package manager. Running `pando hydrate` proactively populates this same cache. Unchanged inputs are skipped, failed recipes are retried, and `pando hydrate --force` deliberately reruns every detected recipe. In watcher mode recipes run on a worker thread after materialization, so installs and downloads do not block snapshot, lease, fetch, or pull processing. Watcher events inside classified derived trees are ignored, so rebuilding `node_modules` or `.venv` does not publish snapshots.

Rehydration is opt-in because package managers can access the network and may execute lifecycle scripts or build hooks from the repository and its dependencies. Enable it only for repositories you trust.

## Reconciling forks

When two devices change the same path from their last shared snapshot, Pando leaves the active authority head untouched and preserves the local tree as a pending fork. The TUI is the primary way to resolve these; the equivalent plumbing lists pending forks for a joined folder:

```sh
pando reconcile ~/Pando/code/project
```

Resolve one explicitly:

```sh
pando reconcile <folder> --fork <snapshot-id> --choice authority
pando reconcile <folder> --fork <snapshot-id> --choice fork
pando reconcile <folder> --fork <snapshot-id> --choice manual
```

`authority` materializes the current authority tree. `fork` publishes the preserved fork as a new child of the current head. `manual` publishes the tree currently on disk after you resolve it yourself. The first two choices refuse if the working tree changed after the fork; this prevents a selection from silently erasing newer edits. Status and the TUI show the number and IDs of pending forks.

## Safety model

- Chunks and manifests are immutable and content-addressed.
- A manifest becomes visible only after all referenced chunks arrive.
- Only the active lease holder can publish.
- A stale trunk is refused even after the previous lease expires.
- A stale trunk three-way merges non-overlapping edits against its last shared snapshot; overlapping paths are reported without overwriting local work, and the local snapshot is retained as an authority-side fork.
- Pull refuses to overwrite local edits.
- Trunk bookkeeping lives outside the repository, so Git operations cannot stash, clean, or check it out.

Audit an authority store without modifying it:

```sh
pando verify --data ~/.local/share/pando/authority
```

The audit rehashes every stored chunk, recomputes every snapshot ID, validates overlay shape and byte lengths, walks parent chains, and checks that every repository head resolves to a snapshot for that repository. For the cleanest point-in-time result, run it while the authority is idle; a concurrent publication can produce a transient mismatch that is safe to retry.

Preview storage reclamation with `pando gc --data ~/.local/share/pando/authority`. Pando retains overlay upserts plus complete `.git` state; files already absorbed by a pushed base are reconstructed from that pinned Git commit during pull, authority restore, and encrypted escape recovery. GC can therefore discard absorbed base-file chunks as well as snapshots unreachable from every head or pending fork and chunks used only by those snapshots. It verifies before reporting. Stop the authority service and pass `--apply` to delete exactly that collectable set; retained head/fork ancestry remains restorable and is verified again afterward.

Restore any retained snapshot into a new path:

```sh
pando restore \
  --data ~/.local/share/pando/authority \
  --snapshot <snapshot-id> \
  --destination ~/Restores/project-snapshot
```

The destination must not already exist. Pando materializes into a sibling staging directory, verifies content hashes while reading, and renames the completed tree into place. It refuses unsafe paths, reserved `.pando/` state, and paths that would traverse symlink ancestors.

Pando captures the portable repository—including `.git`—while preserving classified derived and local-only state independently on each machine. The code-level Phase 1 baseline now includes encrypted authenticated transport, classification, asynchronous multi-ecosystem rehydration with a verified local per-platform artifact CAS, conflict forks and reconciliation, Git remote tracking and force-push rescue, pushed-base chunk compaction, encrypted Git escape recovery, integrity verification, safe restore, unreachable-data GC, and launchd/systemd packaging. Cross-machine/global artifact sharing belongs to the later global CAS phase. Weekly recovery drills, sustained sleep/wake use, all-repository dogfooding, and the two-week control experiment remain elapsed evidence gates; continue dogfooding on disposable clones before valuable repositories.

On macOS and Windows, Pando refuses a snapshot containing paths that differ only by case before materialization begins. This protects case-insensitive filesystems from silently aliasing and overwriting portable files created on a case-sensitive machine.
