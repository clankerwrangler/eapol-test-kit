# Source provenance

The image builds only the `eapol_test` client from upstream `wpa_supplicant 2.11`.
It does not build or install an authentication server.

`runtime/source.env` is the canonical version, URL, and digest manifest:

- Release: `wpa_supplicant-2.11.tar.gz`.
- Upstream endpoint: [the upstream 2.11 release](https://w1.fi/releases/wpa_supplicant-2.11.tar.gz).
- Downloaded archive size: 3,841,433 bytes.
- SHA-256: `912ea06f74e30a8e36fbb68064d6cdff218d8d591db0fc5d75dee6c81ac7fc0a`.
- The archive's `src/common/version.h` declares `VERSION_STR "2.11"`.

The digest was computed from an actual download from the upstream HTTPS endpoint,
not copied from an unverified example or guessed. The build fetches that endpoint,
checks SHA-256 before extraction, checks the embedded version, and then applies
only the checked-in patches with zero fuzz. A release signature is available
upstream, but this kit does not claim an independently verified signing key.
HTTPS origin authentication and the checked-in digest are the provenance controls.

`runtime/licenses/` contains the release's complete top-level `COPYING` and `README`
notices. The final image retains these notices, the source manifest, the build
configuration, and the exact patches under `/usr/local/share/doc/eapol_test/`.
The patches remain subject to the upstream BSD licensing terms.

## Auditable patch scope

Apply these patches in filename order:

1. `0001-protected-secret-file.patch` adds `-F`, disables key and packet dumps
   in that mode, authenticates legacy no-EAP rejections, and emits the terminal
   native result footer. It preserves legacy `-s` and `-S`.
2. `0002-native-certificate-result.patch` adds the optional typed
   `TLS_CERT_CHAIN_FAILURE` callback through the existing EAP/EAPOL bridge and
   the saturating `cert_error` footer field. Diagnostic certificate text has no
   authority over that counter.
3. `0003-network-credential-line-bound.patch` increases the existing network
   line buffer to 64 KiB and omits values at the demonstrated malformed-password
   error sites when key display is disabled. It does not replace the parser or
   reduce the API's credential limits.
4. `0004-protected-attribute-file.patch` adds `-G` through the shared protected
   reader and existing extra-attribute parser/encoder. One shared native append
   helper supports raw opaque rows while preserving the legacy extended-aware
   wrapper. It corrects the existing long-extended fragment copy length, checks
   the assembled managed UDP request budget, and clears owned file, temporary,
   and RADIUS message buffers at their existing cleanup boundaries.

See `INTERFACE.md` for exact grammar, field domains, cleanup limits, and remaining
server interoperability constraints. See `VERIFICATION.md` for evidence tied to
specific source and image snapshots; source inspection is not an authentication
or new-binary test result.

## Build scope

`runtime/eapol_test.config` selects OpenSSL, EAP-TLS, EAP-PEAP, EAP-TTLS,
EAP-MSCHAPv2, EAP-TLS 1.3 support, IPv6, the file configuration backend, and the
upstream control interface. TTLS PAP and non-EAP MSCHAPv2 are part of the TTLS
implementation. The build requires no wireless driver or raw socket.

The builder uses Debian Bookworm build packages. Only the client binary,
Python dependencies, application source, and provenance notices reach the final
`python:3.12-slim-bookworm` stage. The final image explicitly installs the OpenSSL
runtime and CA bundle, not compiler packages. OpenSSL's legacy provider remains
available because MSCHAPv2 requires MD4 and DES; the kit does not lower the TLS
certificate policy to enable those password-protocol primitives.

The existing Python dependency installation uses the root-owned `requirements.lock`
as a required pip constraint. The final image retains that file at
`/app/requirements.lock`; the image check compares every installed package with
its locked version. There is no unlocked installation fallback.

The Python base tag and Debian repositories can receive updates. The dependency
lock pins package versions, not wheel hashes or base-image bytes. This is a pinned
client-source and Python-dependency build, not a claim of bit-for-bit image
reproducibility.
