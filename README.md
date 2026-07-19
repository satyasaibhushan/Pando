# Pando

Pando carries the state between your keyboard and the last push to every machine you use. Git remains history; Pando supplies presence.

Phase 0 was a deliberately small proof: portable macOS and Linux trunks, one always-on authority, append-only whole-tree snapshots, pushed-ref overlays, leases that prevent concurrent writers, and hard refusal when two trunks diverge. It did not encrypt traffic or merge forks.

The implementation and live two-Mac handoff are complete: dirty files, the active branch, index, and stash all materialized on the second machine. Phase 0 is closed; longer dogfooding and the remote-development control experiment move to Phase 1, after the security baseline is usable.

## Build and test

```sh
cargo test
cargo build --release
```

Run the deterministic local handoff demo:

```sh
cargo run -- demo
```

## Two-machine proof

Generate one fabric key, then copy that file securely to every Pando machine. Key generation refuses to overwrite an existing key and creates it with mode `0600` on Unix:

```sh
pando keygen --output ~/.config/pando/fabric.key
export PANDO_KEY=~/.config/pando/fabric.key
```

On the always-on machine, start the authority and allow TCP port 7337 through the local firewall:

```sh
pando serve \
  --bind 0.0.0.0:7337 \
  --data ~/.local/share/pando/authority \
  --key "$PANDO_KEY"
```

Clone the same repository on each trunk. Start a watcher on both, using a stable repository ID and a distinct trunk ID:

```sh
pando watch \
  --repo ~/Code/project \
  --repo-id project \
  --trunk-id macbook \
  --authority tcp://linuxbox.local:7337 \
  --key "$PANDO_KEY"
```

The watcher performs a complete classified-tree scan every 60 seconds as a backstop for missed filesystem notifications. Adjust it with `--full-scan-secs`; event-driven snapshots still use the shorter quiescence window.

For Git repositories, the watcher also runs `git fetch --all --prune` every 30 seconds on a background thread. It updates remote-tracking refs but never checks out, merges, rebases, or pulls. Use `--fetch-secs 0` to disable it or run `pando fetch --repo ~/Code/project` explicitly. Because `.git` is portable state, refreshed remote-tracking refs follow the repository to other trunks. When a remote ref is force-pushed, Pando pins the previous commit under a local `refs/pando/rescue/...` ref so Git garbage collection cannot discard its commit and tree metadata; complete snapshot file content is already retained in Pando's chunk store.

```sh
pando watch \
  --repo ~/Code/project \
  --repo-id project \
  --trunk-id linuxbox \
  --authority tcp://127.0.0.1:7337 \
  --key "$PANDO_KEY"
```

Inspect the fabric with either surface:

```sh
pando status --repo-id project --authority tcp://linuxbox.local:7337
pando tui --repo-id project --authority tcp://linuxbox.local:7337
```

Every TCP RPC now runs inside a Noise `NNpsk0` session using ChaCha20-Poly1305. The shared fabric key authenticates membership and the session encrypts traffic in transit; wrong-key and legacy plaintext clients are rejected. The current self-hosted model assumes the authority machine is trusted, just like the two endpoint Macs: it receives and stores plaintext chunks and manifests. Individual device identities and ciphertext-only authority storage become necessary before a hosted or otherwise untrusted authority.

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

Pando can rebuild classified dependency trees from portable manifests and lockfiles. The first Phase 1 runner recognizes root and nested projects with these exact recipes:

- `package.json` + `package-lock.json` → `npm ci`
- `pyproject.toml` + `uv.lock` → `uv sync --frozen`

Run recipes explicitly:

```sh
pando hydrate --repo ~/Code/project
```

Or opt in to running changed recipes after the watcher applies a remote snapshot:

```sh
pando watch \
  --repo ~/Code/project \
  --repo-id project \
  --trunk-id macbook \
  --authority tcp://linuxbox.local:7337 \
  --key "$PANDO_KEY" \
  --rehydrate
```

Pando invokes only these known executables directly—never through a shell—and caches successful fingerprints outside the repository. Unchanged inputs are skipped, failed recipes are retried, and `pando hydrate --force` deliberately reruns every detected recipe. Watcher events inside classified derived trees are ignored, so rebuilding `node_modules` or `.venv` does not publish snapshots.

Rehydration is opt-in because package managers can access the network and may execute lifecycle scripts or build hooks from the repository and its dependencies. Enable it only for repositories you trust.

## Reconciling forks

When two trunks change the same path from their last shared snapshot, Pando leaves the active authority head untouched and preserves the local tree as a pending fork. List pending forks with the same trunk arguments used by `push`:

```sh
pando reconcile \
  --repo ~/Code/project \
  --repo-id project \
  --trunk-id macbook \
  --authority tcp://linuxbox.local:7337 \
  --key "$PANDO_KEY"
```

Resolve one explicitly:

```sh
pando reconcile <trunk arguments> --fork <snapshot-id> --choice authority
pando reconcile <trunk arguments> --fork <snapshot-id> --choice fork
pando reconcile <trunk arguments> --fork <snapshot-id> --choice manual
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

Restore any retained snapshot into a new path:

```sh
pando restore \
  --data ~/.local/share/pando/authority \
  --snapshot <snapshot-id> \
  --destination ~/Restores/project-snapshot
```

The destination must not already exist. Pando materializes into a sibling staging directory, verifies content hashes while reading, and renames the completed tree into place. It refuses unsafe paths, reserved `.pando/` state, and paths that would traverse symlink ancestors.

Pando captures the portable repository—including `.git`—while preserving classified derived and local-only state independently on each machine. Opt-in npm/uv rehydration, authority verification, and restore-to-new-tree are implemented; fork reconciliation, broader recipe coverage, artifact caching, and scheduled real-repository restore drills remain Phase 1 work, so continue dogfooding on disposable clones before valuable repositories.
