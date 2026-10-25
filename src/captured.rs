//! Request-aware profiles compiled from real browser captures.
//!
//! A profile describes headers, not a certified TLS fingerprint. Transport is an
//! explicit constructor argument. Context belongs to the browser engine: resource
//! destination cannot be inferred reliably from a URL or HTTP method.
use serde::Deserialize;
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    sync::{Arc, Mutex},
};
use url::Url;
use wreq::{
    Method, Version,
    header::{HeaderMap, HeaderName, HeaderValue, OrigHeaderMap},
};

#[path = "captured/catalog.rs"]
mod catalog;

/// Whether research-derived platform variants are acceptable to this caller.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EvidencePolicy {
    NativeOnly,
    AllowDerived,
}

/// Lightweight version catalogue. Loading a profile parses and validates its fixture.
#[derive(Clone, Copy, Debug)]
pub struct ProfileEntry {
    pub profile_id: &'static str,
    pub browser: &'static str,
    /// Chromium build, including for Brave (not the Brave product release number).
    pub chromium_version: &'static str,
    /// Product build (Edge differs from its embedded Chromium build).
    pub product_version: Option<&'static str>,
    pub platform: &'static str,
    pub architecture: &'static str,
    pub capture_mode: &'static str,
    pub verification: &'static str,
    json: &'static str,
}
impl ProfileEntry {
    pub fn load(&self, evidence: EvidencePolicy) -> Result<CaptureProfile, Error> {
        if evidence == EvidencePolicy::NativeOnly && self.verification != "native" {
            return Err(format!("{} is derived, not native-validated", self.profile_id).into());
        }
        let profile = CaptureProfile::from_json(self.json)?;
        if profile.profile_id != self.profile_id || profile.verification != self.verification {
            return Err("catalogue and fixture metadata disagree".into());
        }
        Ok(profile)
    }
    pub fn as_json(&self) -> &'static str {
        self.json
    }
}

pub fn profiles() -> &'static [ProfileEntry] {
    catalog::CATALOG
}

fn version_key(version: &str) -> Vec<u32> {
    version
        .split('.')
        .map(|part| part.parse().unwrap_or(0))
        .collect()
}

/// Fallible capture loading, validation, or request preparation.
pub type Error = Box<dyn std::error::Error + Send + Sync>;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Sample {
    pub protocol: String,
    pub scenario: String,
    pub headers: Vec<(String, String)>,
    pub order: Vec<String>,
}

/// Frozen, inspectable evidence. `derived` profiles are never reported as native.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureProfile {
    #[serde(default)]
    pub profile_id: String,
    #[serde(default)]
    pub chromium_version: String,
    #[serde(default)]
    pub architecture: String,
    #[serde(default)]
    pub capture_mode: String,
    #[serde(default)]
    pub product_version: Option<String>,
    pub schema_version: u32,
    pub browser: String,
    pub platform: String,
    pub verification: String,
    pub captured_at: String,
    pub source_capture: String,
    pub source_sha256: String,
    pub browser_version: String,
    pub identity: serde_json::Value,
    pub transport_verification: String,
    pub sources: Vec<String>,
    pub assumptions: Vec<String>,
    pub samples: Vec<Sample>,
    pub high_entropy_headers: BTreeMap<String, String>,
}

impl CaptureProfile {
    pub fn from_json(json: &str) -> Result<Self, Error> {
        let profile: Self = serde_json::from_str(json)?;
        if profile.schema_version != 1
            || !["native", "derived"].contains(&profile.verification.as_str())
        {
            return Err("unsupported capture schema or verification status".into());
        }
        let mut keys = HashSet::new();
        for sample in &profile.samples {
            if !keys.insert((&sample.protocol, &sample.scenario)) {
                return Err("duplicate capture scenario".into());
            }
            for (key, value) in &sample.headers {
                HeaderName::from_bytes(key.as_bytes())?;
                HeaderValue::from_str(value)?;
                if matches!(
                    key.to_ascii_lowercase().as_str(),
                    "cookie" | "authorization" | "host" | "referer" | "origin" | "content-length"
                ) {
                    return Err("capture contains session-specific headers".into());
                }
            }
            for name in &sample.order {
                HeaderName::from_bytes(name.as_bytes())?;
            }
        }
        for (key, value) in &profile.high_entropy_headers {
            if !key.starts_with("sec-ch-ua-") {
                return Err("invalid high entropy hint".into());
            }
            HeaderName::from_bytes(key.as_bytes())?;
            HeaderValue::from_str(value)?;
        }
        for protocol in [Protocol::Http1, Protocol::Http2] {
            for scenario in [
                "navigation",
                "link",
                "script",
                "style",
                "image",
                "font",
                "fetch",
                "post",
                "cross-fetch",
                "cross-script",
                "hints",
            ] {
                profile.sample(protocol, scenario)?;
            }
        }
        Ok(profile)
    }

    /// Select an immutable full ID, or a convenient browser/major/platform alias.
    /// Aliases choose the highest captured patch within that exact major; they never
    /// snap to another major. Use full IDs for reproducible production selection.
    pub fn select(selector: &str, evidence: EvidencePolicy) -> Result<Self, Error> {
        if let Some(entry) = profiles().iter().find(|p| p.profile_id == selector) {
            return entry.load(evidence);
        }
        let parts: Vec<_> = selector.split('/').collect();
        if let [browser, major, platform] = parts.as_slice() {
            let major: u16 = major.parse().map_err(|_| "invalid browser major")?;
            return Self::find_version(browser, Some(major), platform, evidence);
        }
        Err(
            format!("unknown capture profile: {selector}; inspect profiles() for available IDs")
                .into(),
        )
    }

    fn find_version(
        browser: &str,
        major: Option<u16>,
        platform: &str,
        evidence: EvidencePolicy,
    ) -> Result<Self, Error> {
        let entry = profiles()
            .iter()
            .filter(|p| {
                p.browser == browser
                    && p.platform == platform
                    && p.architecture == "x86_64"
                    && p.capture_mode == "headed"
                    && major.is_none_or(|m| {
                        p.chromium_version
                            .split('.')
                            .next()
                            .and_then(|s| s.parse::<u16>().ok())
                            == Some(m)
                    })
            })
            .max_by_key(|p| version_key(if p.browser == "edge" { p.product_version.unwrap_or(p.chromium_version) } else { p.chromium_version }))
            .ok_or_else(|| {
                format!("no headed x86_64 capture for {browser}/{major:?}/{platform}")
            })?;
        entry.load(evidence)
    }

    pub fn for_major(
        browser: Browser,
        major: u16,
        platform: Desktop,
        evidence: EvidencePolicy,
    ) -> Result<Self, Error> {
        Self::find_version(browser.as_str(), Some(major), platform.as_str(), evidence)
    }

    /// Backwards-compatible latest headed x86_64 fixture. Prefer full IDs when pinning.
    pub fn builtin(browser: Browser, platform: Desktop) -> Result<Self, Error> {
        Self::find_version(
            browser.as_str(),
            None,
            platform.as_str(),
            EvidencePolicy::AllowDerived,
        )
    }

    fn sample(&self, protocol: Protocol, scenario: &str) -> Result<&Sample, Error> {
        self.samples
            .iter()
            .find(|s| s.protocol == protocol.as_str() && s.scenario == scenario)
            .ok_or_else(|| format!("missing capture: {} {scenario}", protocol.as_str()).into())
    }
}

#[derive(Clone, Copy, Debug)]
pub enum Browser {
    Chrome,
    Brave,
    Edge,
}
impl Browser {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Chrome => "chrome",
            Self::Brave => "brave",
            Self::Edge => "edge",
        }
    }
}
#[derive(Clone, Copy, Debug)]
pub enum Desktop {
    Linux,
    Windows,
    MacOS,
}
impl Desktop {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Linux => "linux",
            Self::Windows => "windows",
            Self::MacOS => "macos",
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Protocol {
    Http1,
    Http2,
}
impl Protocol {
    fn as_str(self) -> &'static str {
        match self {
            Self::Http1 => "http/1.1",
            Self::Http2 => "h2",
        }
    }
    fn version(self) -> Version {
        match self {
            Self::Http1 => Version::HTTP_11,
            Self::Http2 => Version::HTTP_2,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Destination {
    Document,
    Script,
    Style,
    Image,
    Font,
    Empty,
}
impl Destination {
    fn as_str(self) -> &'static str {
        match self {
            Self::Document => "document",
            Self::Script => "script",
            Self::Style => "style",
            Self::Image => "image",
            Self::Font => "font",
            Self::Empty => "empty",
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FetchMode {
    Navigate,
    Cors,
    NoCors,
    SameOrigin,
}
impl FetchMode {
    fn as_str(self) -> &'static str {
        match self {
            Self::Navigate => "navigate",
            Self::Cors => "cors",
            Self::NoCors => "no-cors",
            Self::SameOrigin => "same-origin",
        }
    }
}

/// Semantic context, supplied by the engine, not hand-authored headers.
#[derive(Clone, Debug)]
pub struct RequestContext {
    pub destination: Destination,
    pub mode: FetchMode,
    pub initiator: Option<Url>,
    pub user_activation: bool,
    /// Earlier redirect URLs; the least same-site relationship wins.
    pub redirect_chain: Vec<Url>,
}
impl RequestContext {
    pub fn navigation(initiator: Option<Url>, user_activation: bool) -> Self {
        Self {
            destination: Destination::Document,
            mode: FetchMode::Navigate,
            initiator,
            user_activation,
            redirect_chain: vec![],
        }
    }
    pub fn resource(destination: Destination, initiator: Url) -> Self {
        let mode = if matches!(destination, Destination::Font | Destination::Empty) {
            FetchMode::Cors
        } else {
            FetchMode::NoCors
        };
        Self {
            destination,
            mode,
            initiator: Some(initiator),
            user_activation: false,
            redirect_chain: vec![],
        }
    }
    pub fn fetch(initiator: Url) -> Self {
        Self::resource(Destination::Empty, initiator)
    }
}

/// Force replaces only named fields (None removes). Exact skips all profile and
/// negotiation rules; the supplied ordered headers are the entire application
/// header set. HTTP framing/pseudo-headers remain the transport's responsibility.
#[derive(Clone, Debug, Default)]
pub enum SendMode {
    #[default]
    Auto,
    Force(Vec<(String, Option<String>)>),
    Exact(Vec<(String, String)>),
}

#[derive(Debug)]
pub struct PreparedHeaders {
    pub headers: HeaderMap,
    pub order: OrigHeaderMap,
}

/// Per-browser-session hint state; clone shares it, constructing a new policy does not.
#[derive(Clone)]
pub struct HeaderPolicy {
    pub profile: Arc<CaptureProfile>,
    hints: Arc<Mutex<HashMap<String, HashSet<String>>>>,
}
impl HeaderPolicy {
    pub fn new(profile: CaptureProfile) -> Self {
        Self {
            profile: Arc::new(profile),
            hints: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Call after every hop, including redirects. Absent Accept-CH leaves state
    /// unchanged; an empty value clears it. Never learn hints from plain HTTP.
    pub fn observe_response(&self, url: &Url, headers: &HeaderMap) {
        if url.scheme() != "https" {
            return;
        }
        if headers.contains_key("accept-ch") {
            let hints = headers
                .get_all("accept-ch")
                .iter()
                .filter_map(|v| v.to_str().ok())
                .flat_map(|v| v.split(','))
                .map(|v| v.trim().to_ascii_lowercase())
                .filter(|v| self.profile.high_entropy_headers.contains_key(v))
                .collect();
            self.hints
                .lock()
                .expect("hint state poisoned")
                .insert(url.origin().ascii_serialization(), hints);
        }
    }

    pub fn prepare(
        &self,
        method: &Method,
        url: &Url,
        context: &RequestContext,
        protocol: Protocol,
        application: &HeaderMap,
        mode: &SendMode,
    ) -> Result<PreparedHeaders, Error> {
        if let SendMode::Exact(pairs) = mode {
            return ordered_headers(pairs);
        }
        if !matches!(url.scheme(), "http" | "https") {
            return Err("HTTP(S) URL required".into());
        }
        let site = fetch_site(context, url);
        let scenario = match context.destination {
            Destination::Document => {
                if context.initiator.is_some() {
                    "link"
                } else {
                    "navigation"
                }
            }
            Destination::Script => {
                if site == "cross-site" {
                    "cross-script"
                } else {
                    "script"
                }
            }
            Destination::Style => "style",
            Destination::Image => "image",
            Destination::Font => "font",
            Destination::Empty => {
                if *method == Method::POST {
                    "post"
                } else if site == "cross-site" {
                    "cross-fetch"
                } else {
                    "fetch"
                }
            }
        };
        let sample = self.profile.sample(protocol, scenario)?;
        let mut result = ordered_headers(&sample.headers)?;
        // Preserve application data but never import another profile's managed fields.
        for (name, value) in application {
            if !managed(name.as_str()) {
                result.headers.append(name.clone(), value.clone());
            }
        }
        // Content-Type is body/application-dependent, not frozen with a POST sample.
        result.headers.remove("content-type");
        if let Some(value) = application.get("content-type") {
            result.headers.insert("content-type", value.clone());
        }
        result.order = OrigHeaderMap::new();
        for key in &sample.order {
            result.order.insert(key.clone());
        }
        let secure = url.scheme() == "https";
        if secure {
            set(&mut result.headers, "sec-fetch-site", site)?;
            set(&mut result.headers, "sec-fetch-mode", context.mode.as_str())?;
            set(
                &mut result.headers,
                "sec-fetch-dest",
                context.destination.as_str(),
            )?;
            if context.mode == FetchMode::Navigate && context.user_activation {
                set(&mut result.headers, "sec-fetch-user", "?1")?;
            }
            let hints = self.hints.lock().expect("hint state poisoned");
            if let Some(enabled) = hints.get(&url.origin().ascii_serialization()) {
                for name in enabled {
                    if let Some(value) = self.profile.high_entropy_headers.get(name) {
                        set(&mut result.headers, name, value)?;
                    }
                }
                // Captured high-entropy hint order, with navigation-only fields retained.
                if !enabled.is_empty() {
                    let order = &self.profile.sample(protocol, "hints")?.order;
                    let mut keys = order.clone();
                    let position = keys
                        .iter()
                        .position(|v| v.eq_ignore_ascii_case("user-agent"))
                        .unwrap_or(keys.len());
                    if context.destination == Destination::Document {
                        keys.insert(position, "Upgrade-Insecure-Requests".into());
                    }
                    let position = keys
                        .iter()
                        .position(|v| v.eq_ignore_ascii_case("sec-fetch-dest"))
                        .unwrap_or(keys.len());
                    keys.insert(position, "Sec-Fetch-User".into());
                    result.order = OrigHeaderMap::new();
                    for key in keys {
                        result.order.insert(key);
                    }
                }
            }
        } else {
            let names: Vec<_> = result
                .headers
                .keys()
                .filter(|k| {
                    k.as_str().starts_with("sec-ch-") || k.as_str().starts_with("sec-fetch-")
                })
                .cloned()
                .collect();
            for name in names {
                result.headers.remove(name);
            }
        }
        if context.mode == FetchMode::Navigate {
            set(&mut result.headers, "upgrade-insecure-requests", "1")?;
        }
        if let Some(initiator) = &context.initiator {
            // Default strict-origin-when-cross-origin. Engine may force another policy.
            if !(initiator.scheme() == "https" && url.scheme() == "http") {
                let mut referer = initiator.clone();
                referer.set_fragment(None);
                let _ = referer.set_username("");
                let _ = referer.set_password(None);
                let value = if initiator.origin() == url.origin() {
                    referer.to_string()
                } else {
                    format!("{}/", initiator.origin().ascii_serialization())
                };
                set(&mut result.headers, "referer", &value)?;
            }
            if (context.mode == FetchMode::Cors
                && (initiator.origin() != url.origin()
                    || context.destination != Destination::Empty))
                || !matches!(*method, Method::GET | Method::HEAD)
            {
                let origin = initiator.origin().ascii_serialization();
                let tainted = context
                    .redirect_chain
                    .iter()
                    .any(|hop| hop.origin() != url.origin());
                set(
                    &mut result.headers,
                    "origin",
                    if tainted { "null" } else { &origin },
                )?;
            }
        }
        if let SendMode::Force(overrides) = mode {
            for (name, value) in overrides {
                let key = HeaderName::from_bytes(name.as_bytes())?;
                result.headers.remove(&key);
                if let Some(value) = value {
                    result.headers.insert(key, HeaderValue::from_str(value)?);
                }
            }
        }
        // Deterministic order for uncaptured/application-specific names.
        let mut extra: Vec<_> = result
            .headers
            .keys()
            .map(|k| k.as_str().to_string())
            .collect();
        extra.sort();
        for name in extra {
            if !result.order.iter().any(|(key, _)| key.as_str() == name) {
                result.order.insert(name);
            }
        }
        Ok(result)
    }
}

fn managed(name: &str) -> bool {
    name.starts_with("sec-ch-")
        || name.starts_with("sec-fetch-")
        || matches!(
            name,
            "user-agent"
                | "accept"
                | "accept-language"
                | "accept-encoding"
                | "priority"
                | "sec-gpc"
                | "upgrade-insecure-requests"
                | "origin"
                | "referer"
                | "host"
                | "connection"
                | "content-length"
        )
}
fn set(headers: &mut HeaderMap, name: &str, value: &str) -> Result<(), Error> {
    headers.insert(
        HeaderName::from_bytes(name.as_bytes())?,
        HeaderValue::from_str(value)?,
    );
    Ok(())
}
fn ordered_headers(pairs: &[(String, String)]) -> Result<PreparedHeaders, Error> {
    let mut result = PreparedHeaders {
        headers: HeaderMap::new(),
        order: OrigHeaderMap::new(),
    };
    for (name, value) in pairs {
        result.headers.append(
            HeaderName::from_bytes(name.as_bytes())?,
            HeaderValue::from_str(value)?,
        );
        result.order.insert(name.clone());
    }
    Ok(result)
}
fn relationship(a: &Url, b: &Url) -> u8 {
    if a.origin() == b.origin() {
        return 0;
    }
    let domain = |url: &Url| {
        url.host_str()
            .map(|host| psl::domain_str(host).unwrap_or(host).to_string())
    };
    if a.scheme() == b.scheme() && domain(a).is_some() && domain(a) == domain(b) {
        1
    } else {
        2
    }
}
fn fetch_site(context: &RequestContext, target: &Url) -> &'static str {
    let Some(initiator) = &context.initiator else {
        return "none";
    };
    let rank = context
        .redirect_chain
        .iter()
        .chain(std::iter::once(target))
        .map(|url| relationship(initiator, url))
        .max()
        .unwrap_or(0);
    ["same-origin", "same-site", "cross-site"][usize::from(rank)]
}

/// One-hop transport adapter. All header decisions and Accept-CH learning happen
/// here. The embedding engine retains redirect, CORS, cookie and retry ownership.
/// Automatic wreq redirects are disabled so a second hop cannot reuse stale metadata.
#[derive(Clone)]
pub struct CapturedClient {
    client: wreq::Client,
    pub policy: HeaderPolicy,
    protocol: Protocol,
}
impl CapturedClient {
    /// Transport profile is deliberately explicit: builtin captures are newer than
    /// this fork's upstream TLS presets. No silent "nearest version" certification.
    pub fn new(
        profile: CaptureProfile,
        transport: crate::Profile,
        protocol: Protocol,
    ) -> Result<Self, Error> {
        Self::with_builder(wreq::Client::builder(), profile, transport, protocol)
    }
    pub fn with_builder(
        builder: wreq::ClientBuilder,
        profile: CaptureProfile,
        transport: crate::Profile,
        protocol: Protocol,
    ) -> Result<Self, Error> {
        let platform = match profile.platform.as_str() {
            "linux" => crate::Platform::Linux,
            "windows" => crate::Platform::Windows,
            "macos" => crate::Platform::MacOS,
            _ => return Err("unsupported capture platform".into()),
        };
        let builder = builder
            .emulation(
                crate::Emulation::builder()
                    .profile(transport)
                    .platform(platform)
                    .headers(false)
                    .build(),
            )
            .redirect(wreq::redirect::Policy::none())
            .cookie_store(false);
        let builder = match protocol {
            Protocol::Http1 => builder.http1_only(),
            Protocol::Http2 => builder.http2_only(),
        };
        Ok(Self {
            client: builder.build()?,
            policy: HeaderPolicy::new(profile),
            protocol,
        })
    }
    /// Prepare automatically on every hop. Exact suppresses client default headers
    /// and automatic Accept-Encoding insertion as well as the capture policy.
    pub fn request(
        &self,
        method: Method,
        url: &Url,
        context: &RequestContext,
        application: &HeaderMap,
        mode: &SendMode,
    ) -> Result<wreq::RequestBuilder, Error> {
        let prepared =
            self.policy
                .prepare(&method, url, context, self.protocol, application, mode)?;
        let mut request = self
            .client
            .request(method, url.as_str())
            .version(self.protocol.version())
            .default_headers(false)
            .headers(prepared.headers)
            .orig_headers(prepared.order)
            .redirect(wreq::redirect::Policy::none());
        if matches!(mode, SendMode::Exact(_))
            || matches!(mode, SendMode::Force(fields) if fields.iter().any(|(key, value)| key.eq_ignore_ascii_case("accept-encoding") && value.is_none()))
        {
            request = request.gzip(false).brotli(false).deflate(false).zstd(false);
        }
        Ok(request)
    }
    pub async fn send(
        &self,
        method: Method,
        url: &Url,
        context: &RequestContext,
        application: &HeaderMap,
        body: Option<Vec<u8>>,
        mode: &SendMode,
    ) -> Result<wreq::Response, Error> {
        let mut request = self.request(method, url, context, application, mode)?;
        if let Some(body) = body {
            request = request.body(body);
        }
        let response = request.send().await?;
        if !matches!(mode, SendMode::Exact(_)) {
            self.policy.observe_response(url, response.headers());
        }
        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn policy(browser: Browser) -> HeaderPolicy {
        HeaderPolicy::new(CaptureProfile::builtin(browser, Desktop::Linux).unwrap())
    }
    fn url(s: &str) -> Url {
        Url::parse(s).unwrap()
    }
    fn prepare(p: &HeaderPolicy, target: &str, c: &RequestContext) -> PreparedHeaders {
        p.prepare(
            &Method::GET,
            &url(target),
            c,
            Protocol::Http2,
            &HeaderMap::new(),
            &SendMode::Auto,
        )
        .unwrap()
    }
    #[test]
    fn all_browser_platform_pairs_validate_and_retain_provenance() {
        for browser in [Browser::Chrome, Browser::Brave, Browser::Edge] {
            for platform in [Desktop::Linux, Desktop::Windows, Desktop::MacOS] {
                let p = CaptureProfile::builtin(browser, platform).unwrap();
                assert_eq!(p.samples.len(), 22);
                assert_eq!(
                    p.verification == "native",
                    matches!(platform, Desktop::Linux)
                );
                if p.verification == "derived" {
                    assert!(
                        !p.high_entropy_headers
                            .contains_key("sec-ch-ua-platform-version")
                    );
                    assert!(
                        !p.high_entropy_headers
                            .contains_key("sec-ch-ua-full-version-list")
                    );
                }
            }
        }
    }
    #[test]
    fn chrome_and_brave_keep_observed_accept_and_privacy_differences() {
        let c = RequestContext::navigation(None, true);
        let chrome = prepare(&policy(Browser::Chrome), "https://example.com", &c);
        let brave = prepare(&policy(Browser::Brave), "https://example.com", &c);
        assert!(
            chrome.headers["accept"]
                .to_str()
                .unwrap()
                .contains("signed-exchange")
        );
        assert!(
            !brave.headers["accept"]
                .to_str()
                .unwrap()
                .contains("signed-exchange")
        );
        assert_eq!(brave.headers["sec-gpc"], "1");
        assert!(!chrome.headers.contains_key("sec-gpc"));
        assert_eq!(chrome.headers["sec-fetch-user"], "?1");
    }
    #[test]
    fn subresources_never_inherit_navigation_headers() {
        let p = policy(Browser::Chrome);
        for destination in [
            Destination::Script,
            Destination::Style,
            Destination::Image,
            Destination::Font,
            Destination::Empty,
        ] {
            let c = RequestContext::resource(destination, url("https://example.com/page"));
            let h = prepare(&p, "https://cdn.example.com/asset", &c).headers;
            assert!(!h.contains_key("upgrade-insecure-requests"));
            assert!(!h.contains_key("sec-fetch-user"));
            assert_eq!(h["sec-fetch-site"], "same-site");
            assert_eq!(h["sec-fetch-dest"], destination.as_str());
            assert_eq!(h["referer"], "https://example.com/");
        }
    }
    #[test]
    fn public_suffix_scheme_and_redirect_taint_are_respected() {
        let mut c = RequestContext::fetch(url("https://a.co.uk/page"));
        assert_eq!(fetch_site(&c, &url("https://b.co.uk")), "cross-site");
        assert_eq!(fetch_site(&c, &url("https://cdn.a.co.uk")), "same-site");
        assert_eq!(fetch_site(&c, &url("http://a.co.uk")), "cross-site");
        c.redirect_chain.push(url("https://other.test"));
        assert_eq!(fetch_site(&c, &url("https://a.co.uk")), "cross-site");
    }
    #[test]
    fn hints_are_negotiated_per_origin_and_can_be_cleared() {
        let p = policy(Browser::Brave);
        let c = RequestContext::fetch(url("https://example.com/page"));
        let target = "https://example.com/data";
        assert!(
            !prepare(&p, target, &c)
                .headers
                .contains_key("sec-ch-ua-arch")
        );
        let mut response = HeaderMap::new();
        response.insert(
            "accept-ch",
            HeaderValue::from_static("Sec-CH-UA-Arch, Sec-CH-UA-Full-Version-List"),
        );
        p.observe_response(&url(target), &response);
        assert_eq!(prepare(&p, target, &c).headers["sec-ch-ua-arch"], "\"x86\"");
        assert!(
            !prepare(&p, "https://other.example.com", &c)
                .headers
                .contains_key("sec-ch-ua-arch")
        );
        assert!(
            !prepare(&policy(Browser::Brave), target, &c)
                .headers
                .contains_key("sec-ch-ua-arch")
        );
        response.insert("accept-ch", HeaderValue::from_static(""));
        p.observe_response(&url(target), &response);
        assert!(
            !prepare(&p, target, &c)
                .headers
                .contains_key("sec-ch-ua-arch")
        );
    }
    #[test]
    fn insecure_requests_do_not_leak_hints_or_downgrade_referrer() {
        let c = RequestContext::fetch(url("https://example.com/private#fragment"));
        let h = prepare(&policy(Browser::Chrome), "http://example.com/data", &c).headers;
        assert!(!h.contains_key("sec-ch-ua"));
        assert!(!h.contains_key("sec-fetch-site"));
        assert!(!h.contains_key("referer"));
    }
    #[test]
    fn force_and_exact_are_distinct_and_preserve_application_data() {
        let p = policy(Browser::Chrome);
        let target = url("https://example.com");
        let c = RequestContext::navigation(None, false);
        let mut app = HeaderMap::new();
        app.insert("user-agent", HeaderValue::from_static("stale UA"));
        app.insert("cookie", HeaderValue::from_static("session=current"));
        app.insert("x-app", HeaderValue::from_static("value"));
        let forced = p
            .prepare(
                &Method::GET,
                &target,
                &c,
                Protocol::Http2,
                &app,
                &SendMode::Force(vec![
                    ("user-agent".into(), Some("forced".into())),
                    ("accept".into(), None),
                ]),
            )
            .unwrap();
        assert_eq!(forced.headers["user-agent"], "forced");
        assert_eq!(forced.headers["cookie"], "session=current");
        assert!(!forced.headers.contains_key("accept"));
        assert!(!forced.headers.contains_key("sec-fetch-user"));
        let exact = p
            .prepare(
                &Method::GET,
                &target,
                &c,
                Protocol::Http2,
                &app,
                &SendMode::Exact(vec![
                    ("x-only".into(), "1".into()),
                    ("x-only".into(), "2".into()),
                ]),
            )
            .unwrap();
        assert_eq!(exact.headers.len(), 2);
        assert_eq!(exact.headers.get_all("x-only").iter().count(), 2);
        assert!(!exact.headers.contains_key("cookie"));
    }
    #[test]
    fn protocol_specific_priority_and_content_type() {
        let p = policy(Browser::Brave);
        let c = RequestContext::fetch(url("https://example.com/page"));
        let h = p
            .prepare(
                &Method::POST,
                &url("https://example.com/data"),
                &c,
                Protocol::Http1,
                &HeaderMap::new(),
                &SendMode::Auto,
            )
            .unwrap()
            .headers;
        assert!(!h.contains_key("priority"));
        assert!(!h.contains_key("content-type"));
        assert_eq!(h["origin"], "https://example.com");
    }
}

#[cfg(test)]
mod catalog_tests {
    use super::*;

    #[test]
    fn every_catalogue_entry_loads_and_has_a_unique_immutable_id() {
        let mut seen = HashSet::new();
        for entry in profiles() {
            assert!(seen.insert(entry.profile_id));
            let profile = entry.load(EvidencePolicy::AllowDerived).unwrap();
            assert_eq!(profile.chromium_version, entry.chromium_version);
            assert_eq!(profile.product_version.as_deref(), entry.product_version);
            assert_eq!(profile.platform, entry.platform);
            assert_eq!(profile.architecture, entry.architecture);
            assert_eq!(profile.capture_mode, entry.capture_mode);
            assert_eq!(profile.profile_id, entry.profile_id);
            assert_eq!(
                entry.load(EvidencePolicy::NativeOnly).is_ok(),
                entry.verification == "native"
            );
        }
    }

    #[test]
    fn unsupported_versions_never_snap_to_a_different_version() {
        assert!(CaptureProfile::select("chrome/1/linux", EvidencePolicy::AllowDerived).is_err());
        assert!(CaptureProfile::select("brave/999/windows", EvidencePolicy::AllowDerived).is_err());
        assert!(CaptureProfile::select("chrome/nope/linux", EvidencePolicy::AllowDerived).is_err());
        assert!(
            CaptureProfile::select("chrome/148/not-an-os", EvidencePolicy::AllowDerived).is_err()
        );
        assert!(
            CaptureProfile::select("chrome-148-made-up-linux", EvidencePolicy::AllowDerived)
                .is_err()
        );
    }

    #[test]
    fn native_only_rejects_derived_platforms_without_changing_browser_version() {
        let p = CaptureProfile::select("chrome/156/windows", EvidencePolicy::AllowDerived).unwrap();
        assert_eq!(p.verification, "derived");
        assert_eq!(p.platform, "windows");
        assert!(p.chromium_version.starts_with("156."));
        assert!(CaptureProfile::select("chrome/156/windows", EvidencePolicy::NativeOnly).is_err());
    }
}
