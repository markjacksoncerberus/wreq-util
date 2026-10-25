//! Inspect captured profiles: `cargo run -p wreq-util --example profiles --features captured -- list`
use std::io::{self, Write};
use wreq_util::captured::{CaptureProfile, Error, EvidencePolicy, profiles};
fn main() -> Result<(), Error> {
    match run() {
        Err(error)
            if error
                .downcast_ref::<io::Error>()
                .is_some_and(|e| e.kind() == io::ErrorKind::BrokenPipe) =>
        {
            Ok(())
        }
        result => result,
    }
}
fn run() -> Result<(), Error> {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    let args: Vec<_> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str).unwrap_or("list") {
        "list" => {
            writeln!(output, "ID\tEVIDENCE\tMODE")?;
            for p in profiles() {
                writeln!(output, "{}\t{}\t{}", p.profile_id, p.verification, p.capture_mode)?;
            }
        }
        "show" => {
            let selector = args
                .get(1)
                .ok_or("usage: profiles show SELECTOR [--native-only]")?;
            let evidence = if args.iter().any(|s| s == "--native-only") {
                EvidencePolicy::NativeOnly
            } else {
                EvidencePolicy::AllowDerived
            };
            let selected = CaptureProfile::select(selector, evidence)?;
            let entry = profiles()
                .iter()
                .find(|p| p.profile_id == selected.profile_id)
                .ok_or("missing catalogue entry")?;
            writeln!(output, "{}", entry.as_json())?;
        }
        _ => return Err("usage: profiles [list | show SELECTOR [--native-only]]".into()),
    }
    Ok(())
}
