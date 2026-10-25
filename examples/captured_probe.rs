//! Local wire-regression driver for capture/verify.py. Never disables TLS validation for remote hosts.
use url::Url;
use wreq::{
    Method,
    header::{HeaderMap, HeaderValue},
};
use wreq_util::{Profile, captured::*};

#[tokio::main]
async fn main() -> Result<(), Error> {
    let args: Vec<_> = std::env::args().collect();
    let base = Url::parse(&args[1])?;
    if base.host_str() != Some("localhost") {
        return Err("local collector required".into());
    }
    let protocol = if args[3] == "h2" {
        Protocol::Http2
    } else {
        Protocol::Http1
    };
    let client = CapturedClient::with_builder(
        wreq::Client::builder().tls_cert_verification(false),
        CaptureProfile::select(&args[2], EvidencePolicy::NativeOnly)?,
        Profile::Chrome148,
        protocol,
    )?;
    for (path, destination) in [
        ("navigation", Destination::Document),
        ("clicked", Destination::Document),
        ("script.js", Destination::Script),
        ("style.css", Destination::Style),
        ("image.svg", Destination::Image),
        ("font.woff2", Destination::Font),
        ("fetch", Destination::Empty),
        ("post", Destination::Empty),
        ("cross-fetch", Destination::Empty),
        ("cross-script.js", Destination::Script),
        ("hints", Destination::Document),
        ("after-hints", Destination::Empty),
    ] {
        let mut target = base.join(path)?;
        if path.starts_with("cross-") {
            target.set_host(Some("127.0.0.1"))?;
        }
        let context = if path == "clicked" {
            RequestContext::navigation(Some(base.join("navigation")?), true)
        } else if destination == Destination::Document {
            RequestContext::navigation(None, true)
        } else {
            RequestContext::resource(
                destination,
                base.join(if path == "after-hints" {
                    "hints"
                } else {
                    "resources"
                })?,
            )
        };
        let mut application = HeaderMap::new();
        let post = path == "post";
        if post {
            application.insert("content-type", HeaderValue::from_static("text/plain"));
        }
        let response = client
            .send(
                if post { Method::POST } else { Method::GET },
                &target,
                &context,
                &application,
                post.then(|| b"hello".to_vec()),
                &SendMode::Auto,
            )
            .await?;
        response.bytes().await?;
    }
    let context = RequestContext::navigation(None, true);
    client
        .send(
            Method::GET,
            &base.join("exact")?,
            &context,
            &HeaderMap::new(),
            None,
            &SendMode::Exact(vec![("X-Exact".into(), "yes".into())]),
        )
        .await?
        .bytes()
        .await?;
    client
        .send(
            Method::GET,
            &base.join("forced")?,
            &context,
            &HeaderMap::new(),
            None,
            &SendMode::Force(vec![
                ("Accept-Encoding".into(), None),
                ("User-Agent".into(), Some("forced".into())),
            ]),
        )
        .await?
        .bytes()
        .await?;
    Ok(())
}
