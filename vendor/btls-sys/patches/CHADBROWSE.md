# Chrome 150–154 protocol backport

`chadbrowse-chrome150-154.patch` applies after the four original btls patches.
It retains the packaged BoringSSL base and cryptographic implementations.

The implementation comes from these upstream BoringSSL commits:

- [ML-DSA in TLS](https://github.com/google/boringssl/commit/4a3cda40b965bbda7cebf86e35c1ed6890ebcc34)
- [ML-DSA in X.509](https://github.com/google/boringssl/commit/cb784dc9e613938da8a814104040112ed3c92fc9)
- [Server padding](https://github.com/google/boringssl/commit/3c6ffab1743dc0d1f1d43f91e6084be627ca1995)
- [Signature GREASE](https://github.com/google/boringssl/commit/29e593e29165df578ab778269a1f04da2055c32f)

Adaptations: retain the old default signing preferences; use the old SSL_CTX
layout rather than upstream's newer opaque wrapper; place fields and extension
entries around existing btls additions. Unrelated formatting, Go runner changes,
and generated upstream symbol-prefix headers are omitted. btls-sys generates its
own symbol prefixes. New padding/GREASE options default off. The build script
explicitly watches patches and native sources so edits trigger a native rebuild.

The local regression suite is
`cargo test -p chadbrowse-net --features stealth --test tls_milestones`.
It covers all three ML-DSA signatures, RSA and ML-DSA certificate chains,
corrupted and untrusted certificates, padding negotiation/refusal/length checks,
and TLS 1.2 fallback. Reference captures and known fingerprint differences are
documented in `docs/network-stack.md` at the repository root.
