# Runtime verification

## Scope and tested environment

Version 0.1.0 was validated on 2026-09-06 with Docker on Debian 13, Linux
amd64, and an external FreeRADIUS 3.2.10 fixture using TLS 1.2. These results
do not establish TLS 1.3 interoperability, Wi-Fi association, physical
switch-port behavior, or actual VLAN enforcement. FreeRADIUS and browser
tooling remain outside the client kit.

The original authentication results and the later CLI-only deployment
check are separate checkpoints. The license and notice-packaging changes
were first reviewed statically; the CLI deployment build subsequently
verified their installed bytes. No registry image was published as part
of these checks or source delivery.

## CLI-only deployment update

On 2026-09-06, the terminal reader and affected setup, API, and storage
behavior passed 47 focused tests, including 24 real-PTY cases. Coverage
includes complete 4096-character UTF-8 input, delayed-suffix rejection
without echo, configured editing and control characters, and terminal
restoration. The earlier CLI/backend checkpoint passed 243 tests; 11
optional UI tests were skipped, not passed. The setup command uses the
existing password validation and storage path, with an atomic insert that
cannot replace an initialized password.

The replacement Docker Compose build and CLI smoke check passed against
frozen context
`d1e48efa3b68a0c01950566420dc0682fc820e436fe46a97fdc71277f2006ba9`.
A private PTY supplied the two hidden password prompts to the installed
setup command using a generated 4096-character / 16384-byte UTF-8 value.
The one-off setup container had no published ports and started no web or
EAP process. Subsequent HTTP login used the full original value through
the automatically accepted bind address. Host, origin, CSRF, cookie,
health, and private-volume checks passed. The command refused repeated
initialization before accepting input. After container recreation, the
same original password still worked in the same named volume. The exact
temporary test resources were removed.

The test published only on a loopback alias to exercise automatic host
acceptance. README LAN steps use that host-acceptance behavior; they do
not mean a second LAN computer was tested. This check does not establish
real-LAN reachability or HTTPS delivery.
All 34 installed input hashes, including both kit notice documents, and
all 17 locked dependency versions matched the frozen source. The local
image SHA-256 is
`ed2c894b0240ac6071d8f616c8d91001d27edcda144c7d2009104a5fec141347`.
The native binary has the same SHA-256 as the original tested client below.
No RADIUS or full browser matrix was repeated for this bootstrap change,
and no fresh native-suite count is inferred from Docker cache reuse.
The previous CLI-deployment image
`353540d4d665ea47183c2913c06e556037b115dc7952ece27438966fe60fff9d`
remains historical evidence of the earlier short-input checkpoint.
The verification summary was updated after the build; it is not an
installed production input.

## Original authentication outcomes

| Check | Historical evidence and limits |
| --- | --- |
| Backend | 213 API, storage, certificate, migration, and synthetic subprocess tests passed. Independent review checked result evidence, certificate-chain ordering, and secret redaction. |
| Native boundaries | 21 real-binary methods passed as UID/GID 10001 against the native/application checkpoint, including protected inputs, maximum credential lengths, typed certificate evidence, and forged-result controls. These bounded fixtures do not complete all four inner-authentication flows. |
| Direct integration | 15 native authentication cases passed against the external FreeRADIUS fixture: all four methods, password and certificate negatives. |
| HTTP API integration | 18 API checks passed on the matching application image, covering all four methods, negative outcomes, timeout classification, cancellation, single-run enforcement, private-attribute preservation, and sanitized storage and exports. |
| Final browser | Four positive cases passed through Chromium on the CSS-refresh image: EAP-TLS, PEAP-MSCHAPv2, TTLS-PAP, and TTLS-MSCHAPv2. Each had exit 0, authenticated RADIUS accept, peer success, and matching MPPE keys. Sanitized report downloads and login/logout/storage checks passed. |
| Container | Locked dependencies, installed-input correspondence, read-only root, UID/GID 10001, zero effective capabilities, no-new-privileges, zero core limits, private writable mounts, and HTTP startup passed. The image contained no compiler or authentication-server tools. |
| Compose | Fresh setup, health, named-volume ownership, web-password persistence, and saved-record persistence passed on the earlier baseline, not on a rebuilt CSS-refresh image. No RADIUS request ran in this smoke check. |

Local Chromium checks also covered authentication, profiles, certificates,
and protected attributes. The final Docker browser check included desktop
and 390 px history layouts. At 390 px, the table scrolled within its wrapper
without widening the page, and all five columns and actions remained
readable. Geometry checks and visual review passed.

## Historical snapshot correspondence

The following hashes identify locally tested historical artifacts, not
registry references or a promise that a rebuild is byte-identical:

| Artifact | SHA-256 |
| --- | --- |
| Native/application checkpoint image | `348129c9761245ddd794e876b25e113e3439a767dd3801bea105c7fb2c02b907` |
| Final CSS-refresh image | `6233079327df42bce81f69eb8486a8ff5c63d9e86b6a8ba6b44b11c6d913c56f` |
| Native client binary in both images | `6b10e7423b60c772ac7eb8165049324f4c30f24dfa53d7831d4a1ab46e7c39e1` |
| Final history stylesheet | `c579a8aa5110c679ee0a6775078965e7e6ff0d99e06bbcb9ff9f2804a0ee28d8` |
| Corrected native test source | `f4557f7c8ee19fd3e18df5dfa674484eaa132a0f51c6cedd84c3f6d50614b033` |

The only product-code change between those two images was the history-table
stylesheet. All other installed inputs, the native binary, and all 17
locked dependency versions matched. The final HTTP-served stylesheet
matched the frozen source bytes. The verification document was updated
after the build; it was not an installed production input.

The CSS-refresh build ran all 21 native methods with the corrected test
source. Fresh container and HTTP checks and the four browser-positive cases
passed. The unchanged non-root 21-method suite and negative API matrix were
not repeated for the CSS correction. The complete direct and API matrices
belong to the preceding matching application checkpoint.

The original license and notice-packaging changes left the client and
application code unchanged. These two historical image hashes do not
include the added kit notices; the separate CLI deployment image does.

## Failed-test lessons and earlier baseline

The first non-root native run encountered a fixture setup error: the empty
attribute-file case tried to overwrite the previous maximum-size file
after making it read-only. That failed attempt was not a pass. The
correction creates a fresh generated filename for each attribute file; it
does not relax file protections or change production code. All 21 methods
then passed against the same immutable binary as UID/GID 10001. The
CSS-refresh build includes that corrected test source.

The earlier Compose baseline predates the typed certificate counter,
64 KiB network reader, and protected attribute transport. Isolated probes
reproduced maximum-password failures and malformed-password disclosures
in that baseline. The later source fixes do not depend on the incorrect
hypothesis that a truncated physical-line suffix is reparsed. The baseline
Compose pass does not establish that the later native controls passed in
the older binary, and it is not a fresh-image EAP result.

The native boundary suite verifies exact secret and credential bytes,
protected-file rejection, ordered raw attributes, managed packet bounds,
authenticated versus forged replies, typed certificate failures, and
terminal result evidence. Its four-method ClientHello checks alone are not
proof of complete authentication; that evidence comes from the separate
integration and browser checks. Fixtures generate private values at
runtime. Private credentials, fixture state, raw outputs, and internal
receipts are not part of the source distribution.

## Source provenance and reproducibility limits

The canonical build verifies the pinned wpa_supplicant 2.11 archive digest
and embedded version, applies all four patches with zero fuzz, and builds
only `eapol_test`. A release signature is available upstream, but this kit
does not claim an independently verified signing key. HTTPS origin
authentication and the checked-in digest are the source provenance controls.

The Python dependency lock pins versions, not wheel hashes. The Python
base tag and Debian repositories can change. This is a pinned client-source
and dependency-version build, not a bit-for-bit image reproducibility claim.
See `SOURCE.md` for provenance and `INTERFACE.md` for native boundary and
interoperability limits.
