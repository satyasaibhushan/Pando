# Pando

Pando carries the state between your keyboard and the last push to every machine you use. Git remains history; Pando supplies presence.

Phase 0 is a deliberately small proof: macOS and Linux trunks, one always-on authority, append-only whole-tree snapshots, pushed-ref overlays, leases that prevent concurrent writers, and hard refusal when two trunks diverge. It does not yet encrypt content or merge forks.

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

On the always-on machine, start the authority and allow TCP port 7337 through the local firewall:

```sh
pando serve --bind 0.0.0.0:7337 --data ~/.local/share/pando/authority
```

Clone the same repository on each trunk. Start a watcher on both, using a stable repository ID and a distinct trunk ID:

```sh
pando watch \
  --repo ~/Code/project \
  --repo-id project \
  --trunk-id macbook \
  --authority tcp://linuxbox.local:7337
```

```sh
pando watch \
  --repo ~/Code/project \
  --repo-id project \
  --trunk-id linuxbox \
  --authority tcp://127.0.0.1:7337
```

Inspect the fabric with either surface:

```sh
pando status --repo-id project --authority tcp://linuxbox.local:7337
pando tui --repo-id project --authority tcp://linuxbox.local:7337
```

The Phase 0 transport is unauthenticated plaintext and must only be used on localhost or a trusted private network such as Tailscale. Encryption and device enrollment belong to Phase 1.

## Safety model

- Chunks and manifests are immutable and content-addressed.
- A manifest becomes visible only after all referenced chunks arrive.
- Only the active lease holder can publish.
- A stale trunk is refused even after the previous lease expires.
- Pull refuses to overwrite local edits.
- `.pando` is local bookkeeping and is never captured.

Phase 0 captures the complete repository—including `.git`—because classification and rehydration arrive in Phase 1. Test on disposable clones before dogfooding it on valuable work.
