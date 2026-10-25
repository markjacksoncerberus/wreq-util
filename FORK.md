# Shared browser emulation fork

This repository owns the browser profiles and captures formerly maintained inside
Chadbrowse. The full HTTP/TLS transport now lives in the sibling `../wreq` fork,
which also owns the required HTTP/2 and btls-sys patches. It does not depend on Chadbrowse or its JavaScript,
DOM, renderer or application crates. Migration source: Chadbrowse commit
`c7e9ccf7515b18d4a905a6a99b7f6bb2f6e64a77` (`vendor/wreq-util` and supporting
`vendor/wreq`, `vendor/http2`, `vendor/btls-sys`). Original licenses and provenance
are retained. The library baseline is upstream wreq-util 3.0.0-rc.12.

## Use from another local project

Place this repository and our full `wreq` fork next to the consuming project. Cargo only applies patches
from the consuming workspace root, so add all four entries there:

```toml
[dependencies]
wreq = "=6.0.0-rc.29"
wreq-util = { version = "=3.0.0-rc.12", features = ["captured"] }

[patch.crates-io]
wreq-util = { path = "../wreq-util" }
wreq = { path = "../wreq" }
http2 = { path = "../wreq/vendor/http2" }
btls-sys = { path = "../wreq/vendor/btls-sys" }
```

For Git dependencies after publishing the local changes, use
`https://github.com/markjacksoncerberus/wreq-util` for the wreq-util patch, and
`https://github.com/markjacksoncerberus/wreq` for wreq/http2/btls-sys. Pin a revision
for each repository. Cargo locates the named support packages inside wreq.
Keep all four patches: Chrome 149–154 presets use custom TLS fields, and
request-specific HTTP/2 priority needs the patched transport. The wreq manifest
pins HTTP/2, wreq-proto and btls-sys exactly to avoid registry drift.
Commit the consumer's Cargo.lock and build with `--locked`.

No Chadbrowse checkout is needed; the sibling `../wreq` checkout is required. The fork's root patches also support building
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

`CaptureProfile::chromium_transport_profile()` returns the same supported
Chromium-major preset used by Chadbrowse. It errors for header-only captures
above 154, so callers cannot accidentally claim newer transport support.
