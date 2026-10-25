# Shared browser emulation fork

This repository owns the browser profiles, captures and transport patches formerly
maintained inside Chadbrowse. It does not depend on Chadbrowse or its JavaScript,
DOM, renderer or application crates. Migration source: Chadbrowse commit
`c7e9ccf7515b18d4a905a6a99b7f6bb2f6e64a77` (`vendor/wreq-util` and supporting
`vendor/wreq`, `vendor/http2`, `vendor/btls-sys`). Original licenses and provenance
are retained. The library baseline is upstream wreq-util 3.0.0-rc.12.

## Use from another local project

Place this repository next to the consuming project. Cargo only applies patches
from the consuming workspace root, so add all four entries there:

```toml
[dependencies]
wreq = "=6.0.0-rc.29"
wreq-util = { version = "=3.0.0-rc.12", features = ["captured"] }

[patch.crates-io]
wreq-util = { path = "../wreq-util" }
wreq = { path = "../wreq-util/vendor/wreq" }
http2 = { path = "../wreq-util/vendor/http2" }
btls-sys = { path = "../wreq-util/vendor/btls-sys" }
```

For a Git dependency after publishing this fork's changes, replace each patch's
`path` with `git = "https://github.com/markjacksoncerberus/wreq-util"` and the same
pinned `rev`. Cargo locates each named package within the repository. Keep all four
patches: the Chrome 149–154 presets use custom TLS fields, and request-specific
HTTP/2 priority needs the patched transport. The supporting wreq manifest pins
HTTP/2, wreq-proto and btls-sys exactly to avoid silently resolving newer registry versions.
Commit the consumer's Cargo.lock and build with `--locked`.

No Chadbrowse checkout is needed. The fork's root patches also support building
and testing this repository directly:

```sh
cargo test --lib --features captured
cargo build --examples --features captured
python3 -m unittest discover -s capture -p 'test_*.py'
python3 -m venv /tmp/wreq-capture-env
/tmp/wreq-capture-env/bin/pip install -r capture/requirements.txt
/tmp/wreq-capture-env/bin/python capture/verify.py
```

`verify.py` finds the Cargo target directory through metadata (including
CARGO_TARGET_DIR). Use `--probe /absolute/path/to/captured_probe` for a separately
built binary. It compares HTTP/1.1 and HTTP/2 headers against all native captures
using localhost only.

See [CAPTURED.md](CAPTURED.md) for the 54 Chrome 148–156 / Brave 150–154 / Edge 151–154 header
profiles, evidence policies, and adapter usage. Transport presets extend through
Chrome 154; captured headers for 155–156 do not certify matching TLS fingerprints.
The embedding browser still owns JavaScript identity, cookies, redirects and
profile selection. Extraction does not automatically select a different profile.
