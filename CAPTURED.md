# Capture-backed emulation fork

This independent fork extends `wreq-util` 3.0.0-rc.12, migrated from Chadbrowse.
Upstream copyright, license, provenance and existing transport patches are retained.
Consumers opt into this fork without changing their selected browser identity automatically.

The `captured` feature adds `wreq_util::captured`. It contains native Linux Chrome, Brave
and Edge header fixtures, research-derived Windows/macOS x86_64 variants, a
request policy, and a one-hop client adapter. Existing upstream profiles remain
available. The new adapter is opt-in; consumers using plain `wreq::Client` do not
receive request-aware behavior merely by selecting an `Emulation`.

## Use

```rust
use wreq_util::{Profile, captured::*};
use wreq::{Method, header::HeaderMap};
use url::Url;

# async fn example() -> Result<(), Error> {
let fixture = CaptureProfile::builtin(Browser::Brave, Desktop::Linux)?;
// An explicit transport choice, NOT a claim that Chrome148 TLS matches Brave154.
let client = CapturedClient::new(fixture, Profile::Chrome148, Protocol::Http2)?;
let url = Url::parse("https://example.com/")?;
let context = RequestContext::navigation(None, true);
let response = client.send(Method::GET, &url, &context, &HeaderMap::new(), None,
                           &SendMode::Auto).await?;
# let _ = response;
# Ok(()) }
```

Browser engines should construct `RequestContext` internally at navigation,
resource-loader and fetch boundaries. Their users never need to select header
sets. A URL alone cannot distinguish a script from a fetch or a navigation.
`RequestContext::resource` selects normal modes for scripts/styles/images/fonts;
module scripts and CORS-enabled elements must set `context.mode = FetchMode::Cors`.
`RequestContext::fetch` represents fetch/XHR. Form navigations use navigation
context and the actual method/body. Context includes activation and redirect history.

`HeaderPolicy::prepare` is available separately for engines with their own
transport. It selects the resource/protocol fixture, replaces stale browser-owned
headers, calculates schemeful site relationships using the Public Suffix List,
sets default strict-origin-when-cross-origin referrers, and adds only negotiated
high-entropy hints. `observe_response` learns `Accept-CH` per HTTPS origin and
session. A new policy starts clean; clones share state.

- **Auto:** captured browser headers win; application headers/body remain caller-owned.
- **Force:** named replacements or removals run after automatic rules. Use this for
  an explicit Accept, referrer-policy result, priority, or site-specific override.
- **Exact:** the supplied ordered list is the complete application header set;
  suppresses profile/default headers, hint learning and automatic Accept-Encoding.
  Does not promise byte-for-byte TLS, HTTP framing or HTTP/2 pseudo-header replay.
  The transport still produces necessary Host/authority and body framing.

The adapter disables automatic redirects and cookie storage, including on a
caller-supplied builder. The engine owns cookies, credentials, CORS/preflight,
redirect following and retries. On each redirect, update URL/method/body and append
the prior URL to context.redirect_chain, then call send again. This prevents a
transport-level redirect from replaying stale metadata to another origin. Calling
`request()` and then sending the returned raw builder requires the engine to call
`observe_response`; `send()` does that automatically.

## Version selection and platform coverage

The catalogue includes Chrome **148–156**, Brave based on Chromium **150–154**,
and Microsoft Edge **151–154**.
There is one native headed Linux x86_64 capture per major, plus research-derived
Windows x86_64 and macOS Intel variants: **54 selectable profiles**. Brave selection
uses the Chromium version, not its separate 1.xx product release number.

```rust
let chrome = CaptureProfile::select("chrome/148/linux", EvidencePolicy::NativeOnly)?;
let brave = CaptureProfile::select("brave/153/windows", EvidencePolicy::AllowDerived)?;
let pinned = CaptureProfile::select(
    "chrome-148.0.7778.178-linux-x86_64", EvidencePolicy::NativeOnly)?;
```

`profiles()` lists lightweight `ProfileEntry` records. `entry.load(evidence)` loads
and validates a fixture. `CaptureProfile::for_major(browser, major, platform,
evidence)` offers typed selection. An unavailable version errors; there is no
nearest-version fallback. A `browser/major/platform` alias selects the newest
captured patch **within that major**, headed x86_64 only. Pin a full ID when patch
selection must stay fixed. `builtin(browser, platform)` remains a convenience for
the newest captured headed x86_64 build, allowing derived platforms as before.

```sh
cargo run -p wreq-util --example profiles --features captured -- list
cargo run -p wreq-util --example profiles --features captured -- show chrome/148/linux --native-only
cargo run -p wreq-util --example profiles --features captured -- show brave/153/windows
```

`fixtures/catalog.json` and `src/captured/catalog.rs` are generated from the raw
captures by `capture/freeze.py`. Full IDs include browser, actual Chromium build,
platform and architecture. Headless references receive a separate `-headless`
suffix; they cannot silently replace headed evidence. Native Windows/macOS
captures take precedence over derived profiles with the same ID. Duplicate native
captures for an ID are rejected for explicit reconciliation.

For Edge, full profile IDs use the actual Edge product build (for example
`edge-154.0.4258.62-linux-x86_64`). `product_version` retains that build while
`chromium_version` records the distinct Chromium full version observed in Client
Hints. Alias selection never confuses those build numbers; newer Edge patches
within a major are ordered by Edge product version. The Edge `uaFullVersion` JS
hint is the product build, while its Chromium brand retains the Chromium build.

Raw files retain ordered wire-received headers, HTTP/2 SETTINGS, negotiated TLS
version/cipher, browser identity and capture environment. They are synthetic
localhost requests, not private browsing sessions. The compiled JSON includes the
raw capture's SHA-256, date, assumptions, and sources. The native fixture is tied
to the recorded browser/settings/locale, not every installation of that browser.

Windows/macOS variants change the frozen UA platform token, navigator platform,
and low-entropy platform hint according to these primary sources:

- https://www.chromium.org/updates/ua-reduction/
- https://github.com/brave/brave-browser/wiki/User-Agents
- https://wicg.github.io/ua-client-hints/

Resource headers and ordering are inherited from Linux, explicitly unverified on
those operating systems. Unknown OS versions and platform-specific full browser
build hints are omitted instead of invented. These are useful starting profiles,
not native Windows/macOS certification. Apple Silicon is not covered by the Intel
variant. Brave's site-specific brand suppression is not captured by generic rules.

The existing local transport presets extend through Chrome154. This feature does **not**
certify newer TLS emulation, synthesize new transport fingerprints, implement HTTP/3,
Critical-CH retries, cross-origin Permissions-Policy delegation, or every browser
request-priority decision. Captured HTTP/1.1 and HTTP/2 profiles are selected
explicitly and the adapter pins the transport protocol to avoid silent mismatch.
JS identity is exposed as fixture data but must be adopted by the embedding engine;
changing HTTP headers alone does not change a JS runtime's navigator.

## Reproduce and refresh

Official Chrome was installed locally from Google's Linux `.deb` at
`~/.local/opt/google-chrome/opt/google/chrome/google-chrome`. Brave uses
`/usr/bin/brave-browser`. No system browser or user profile was replaced.

```sh
python3 -m venv /tmp/wreq-capture-env
/tmp/wreq-capture-env/bin/pip install -r capture/requirements.txt
/tmp/wreq-capture-env/bin/python capture/capture.py \
  --browser /usr/bin/brave-browser --product brave
/tmp/wreq-capture-env/bin/python capture/capture.py \
  --browser "$HOME/.local/opt/google-chrome/opt/google/chrome/google-chrome" --product chrome
python3 capture/freeze.py
cargo test -p wreq-util --lib --features captured
```

Capture requires Python, OpenSSL, the browser binary and a graphical session for
headed capture. `--headless` is available and recorded; do not relabel it as headed.
The tool uses temporary profiles and a temporary TLS certificate, with a narrowly
scoped SPKI trust exception. It sends real requests to a local TLS server; no
interception proxy rewrites the browser's connection. Playwright supplies launch
flags; this is an automated headed reference, not a claim of zero automation effects.
The fixtures cover direct/link navigation, redirects in raw evidence, scripts,
styles, images, fonts, fetch, POST, cross-site requests and Client Hints negotiation.
Review raw diffs and derived assumptions before freezing a new browser release.

To verify transmission rather than just the policy's in-memory output:

```sh
cargo build -p wreq-util --example captured_probe --features captured
/tmp/wreq-capture-env/bin/python capture/verify.py
```

This starts a local TLS collector and compares ordered regular headers on 28
requests per native capture, including force/exact behavior. Only ephemeral port numbers are
normalized. It does not normalize away browser-specific headers or header order.
TLS cipher-suite/extension parity and HTTP/2 frame parity are outside this header
comparison; the stored native SETTINGS remain evidence for future transport work.


## Install and capture historical official versions

```sh
python3 capture/install.py chrome 148
# prints ~/.cache/wreq-capture/chrome/<full-version>/linux64-stable/installation.json
python3 capture/install.py brave 1.95.104
# prints ~/.cache/wreq-capture/brave/1.95.104/linux64/installation.json
/tmp/wreq-capture-env/bin/python capture/capture.py \
  --product chrome --installation /path/to/installation.json
python3 capture/freeze.py
```

The installer resolves Linux stable versions through Google's VersionHistory API
and downloads regular Chrome `.deb` packages directly from `dl.google.com` into a
user cache. Brave comes from official GitHub release ZIPs, checked against the
published SHA-256 when supplied. Neither replaces the user's installed browser.
The raw capture records download provenance and the archive digest. Versions and
architectures are taken from the actual browser/environment; this is not UA string
substitution. Native capture refuses to overwrite an existing version unless
`--replace` is explicit.

Chrome for Testing is **not** substituted for standard Chrome: our Chrome 148 test
build emitted only Chromium and GREASE brands, unlike regular Google Chrome. On
Windows/macOS, supply an installed regular Google Chrome binary with `--browser`.
The Brave installer also supports official Windows/macOS ZIPs; those installer
branches have not been exercised on this Linux host. The raw collector supports
native platform/architecture metadata; import its `.raw.json` into `fixtures/` and
freeze again to promote matching derived profiles. ARM64 captures receive distinct
IDs and never overwrite Intel profiles.

Official version source: https://developer.chrome.com/docs/web-platform/versionhistory/guide

## Quick endpoints versus native validation

- https://tls.peet.ws/api/all reports observed headers plus TLS and HTTP/2 details.
  It is useful for a quick inspection of an emitted profile. Sending a Windows UA
  from Linux does **not** validate it against Windows Chrome or Brave. Compare with
  the same endpoint reached by an actual native browser, using the same request
  context. One navigation still does not validate the full fixture suite.
- BrowserStack's Playwright service offers Chrome on Windows/macOS through its
  authenticated remote browser endpoint. Its documented browser list does not
  include Brave. Available versions must be checked against the provider catalogue.
  https://www.browserstack.com/docs/automate/playwright/browsers-and-os
  https://www.browserstack.com/docs/automate/playwright/playwright-capabilities
- GitHub-hosted Windows and macOS runners can run official Chrome/Brave and this
  collector on the same machine. This covers both products without a TLS-terminating
  tunnel between browser and collector. Native captures need their real OS,
  architecture and headed/headless mode recorded. A hosted run has not been started
  from this checkout.
  https://docs.github.com/en/actions/reference/runners/github-hosted-runners

A browser-cloud session is the source of native traffic; a fingerprint endpoint
is the observer. Avoid treating a generic “looks like Chrome” score as a reference
capture. Header parity, HTTP/2 settings and TLS parity are separate checks.

## Microsoft Edge capture refresh

Edge Linux packages are obtained from Microsoft's official package index and
verified against its published SHA-256 before extraction into a user cache:

```sh
python3 capture/install.py edge 154
# Use the printed installation.json path; capture uses a fresh temporary profile.
python3 capture/capture.py --product edge --installation /path/to/installation.json
python3 capture/freeze.py
```

Edge 151–154 were captured headed on Linux x86_64 under an isolated Xvfb display.
The Windows/macOS Intel variants remain explicitly derived. Generic localhost
captures do not model Edge's site-specific user-agent overrides. See
[Microsoft's identity guidance](https://learn.microsoft.com/en-us/microsoft-edge/web-platform/user-agent-guidance).
The browser engine uses the corresponding Chromium-major transport preset;
these header captures do not certify a separate native Edge TLS fingerprint.
