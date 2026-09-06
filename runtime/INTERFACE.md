# Client interface

Use `/usr/local/bin/eapol_test` as a non-root UDP RADIUS client. It does not need
host networking, a wireless interface, raw sockets, or Linux capabilities.

## Invocation

Launch an argument array, not a shell command. Replace the documentation address
and `RUN_ID` with the validated target and owned run directory:

```text
eapol_test -c /tmp/eapolkit-runs/RUN_ID/network.conf -a 192.0.2.10 -p 1812 -F /tmp/eapolkit-runs/RUN_ID/radius-secret -G /tmp/eapolkit-runs/RUN_ID/attributes -t 30 -r 0
```

`-a` accepts an IP literal, not a DNS name. Resolve DNS before launch and pass the
selected address. The build includes IPv6. `-p` selects the destination port.
`-t` is the client's timeout in seconds; retain the application's independent
overall deadline. `-r 0` performs no reauthentication. Do not use `-n`: it changes
the success criteria by allowing absent MPPE keys. NAS-IP-Address is a RADIUS
attribute, not the packet source address; upstream `-A` controls source binding.

## Protected secret input

The additive `-F PATH` option reads the exact secret bytes from a protected file:

- Use 1 through 4096 exact bytes. Only NUL is invalid. CR, LF, and all other
  whitespace are preserved without trimming or normalization. The limit counts
  bytes, not Unicode characters; the application encodes UTF-8 before checking it.
- Use a regular, single-link file owned by the process's effective UID.
- Set the mode to `0400` or `0600`. The parent run directory must also be private.
- Symlinks, devices, directories, FIFOs, oversized files, and empty files fail.
- Repeated `-F` and combined `-s`/`-F` fail. Error messages contain neither values
  nor paths. The option does not read a secret from the environment.
- Remove the per-run file after the owned child exits. File creation, directory
  protection, and deletion remain application responsibilities.

The file descriptor uses `O_NOFOLLOW`, `O_NONBLOCK`, and `O_CLOEXEC`. File input
allocates a bounded buffer and clears its full allocation on rejection. On valid
input, upstream copies the bytes into its RADIUS client configuration. The patch
immediately clears the input buffer, clears the client-owned copy during normal
cleanup, and registers an `atexit` cleanup for ordinary early returns. Handled
termination during the event loop takes the normal cleanup path. SIGKILL, abort,
and host failure cannot guarantee userspace cleanup. The Compose core-size limit
is zero; host administrators and same-UID code remain trusted.

Upstream already uses `-S` to save configuration, so this patch does not repurpose
it. Both upstream `-S` and legacy `-s` behavior remain available. The web app uses
neither of those options.

## Network configuration

Use one `network={...}` block with `key_mgmt=IEEE8021X`. The required methods map
as follows:

| Profile | `eap` | `phase2` | Additional material |
| --- | --- | --- | --- |
| EAP-TLS | `TLS` | Omit | Client certificate and matching private key |
| PEAP-MSCHAPv2 | `PEAP` | `"auth=MSCHAPV2"` | Password |
| TTLS-PAP | `TTLS` | `"auth=PAP"` | Password |
| TTLS-MSCHAPv2 | `TTLS` | `"auth=MSCHAPV2"` | Password |

For TTLS, `autheap=MSCHAPV2` selects inner **EAP**, which is a different method
from the requested non-EAP `auth=MSCHAPV2` profile.

Encode `identity`, `anonymous_identity`, and `password` as unquoted hexadecimal
UTF-8 bytes. The generic upstream string parser supports this encoding, including
quotes, backslashes, and newline bytes in the original credential. Do not prefix
plain password hex with `hash:`: that prefix selects a precomputed NT hash.
Generated configuration still contains recoverable credentials and stays private.

The existing network-block reader has a 64 KiB line buffer. This includes the
32768 hex digits required for a 4096-character password when every character
encodes to four UTF-8 bytes. This is a parser capacity, not a smaller API limit.

Set `ca_cert` to the run's validated server trust file and `domain_match` to the
expected full server DNS name. Set `client_cert` and `private_key` for EAP-TLS.
Do not accept arbitrary paths, engines, modules, or other configuration directives
from web inputs. Use `fragment_size` for EAP fragmentation and `eapol_flags=0` for
this RADIUS test client.

TLS controls are space-separated `phase1` parameters. Disable TLS 1.0 and 1.1
with `tls_disable_tlsv1_0=1 tls_disable_tlsv1_1=1`. To cap TLS at 1.2, add
`tls_disable_tlsv1_3=1`. To require TLS 1.3, also disable TLS 1.2 and explicitly
set `tls_disable_tlsv1_3=0`. The build includes EAP-TLS 1.3; upstream PEAP and
TTLS disable TLS 1.3 by default for interoperability. Explicit TLS 1.3 use with
those tunneled methods remains subject to server interoperability. Do not use
`tls_disable_time_checks=1` to support expired client-certificate tests; that
option disables server-certificate time checks too.

## Extra RADIUS attributes

The application passes **all** generated and extra attribute values through one
protected `-G PATH` file. It never places an attribute value in `-N` arguments.
Use this exact ASCII grammar for each row:

```text
TYPE:x:HEX
```

- `TYPE` has one through three decimal digits and a numeric value from 1 to 255.
- The separator and syntax are exactly `:x:`. `HEX` has an even number of ASCII
  hexadecimal digits, including zero digits. Uppercase and lowercase digits work.
  Do not add `0x`, spaces, comments, quotes, CR, or other delimiters.
- Each value contains 0 through 253 decoded bytes. NUL and newline **value bytes**
  work when encoded as hex; a literal NUL or CR in the file does not.
- Separate rows with LF. One final LF is optional. Empty rows are invalid. An
  empty file means zero extra attributes.
- Use at most 64 rows, 512 bytes per row excluding LF, and 32832 total file bytes.
  Never truncate a row or value to fit.
- Use a regular, single-link file owned by the process's effective UID, with
  mode `0400` or `0600`, in the private run directory. The shared protected reader
  uses `O_NOFOLLOW`, `O_NONBLOCK`, and `O_CLOEXEC`, and checks the bounded exact
  file length. It rejects links, devices, directories, FIFOs, and unsafe modes.
- Use exactly one `-G` with `-F`. Repeated `-G`, mixed `-G`/`-N`, and `-G` without
  `-F` fail before authentication. Errors contain no attribute values or paths.

File order is extra-attribute wire order. Duplicates remain distinct. Each row
uses the existing hexadecimal encoder and one ordinary two-byte RADIUS attribute
header. IDs 26 and 241 through 246 carry **exact opaque bytes**; the client does
not guess nested vendor or extended schemas. The caller supplies any required
subtype/flags bytes as part of that opaque value. The shared native append helper
keeps its extended-aware `u16` wrapper for legacy callers and exposes a thin raw
`u8` wrapper for protected input; it does not duplicate packet serialization.

An extra row suppresses the corresponding built-in default only for IDs 4, 31,
12, 61, 6, and 77. It does not suppress automatic User-Name, Message-Authenticator,
EAP-Message, EAP-Key-Name, or copied State. The application controls which of those
protocol-owned attributes it permits as explicit extra rows.

The complete assembled protected request, including defaults, EAP fragments,
and returned State, must fit 65507 bytes before send. This is the IPv4-compatible
UDP payload ceiling, not a 4096-byte file limit. A failed preparation terminates
with a fixed error and sends no partial packet. A server can impose a smaller
packet limit; accepting a file does not promise that a server accepts its data.
The upstream 4096-byte constant limits **incoming** client packets, not outgoing
attribute-file capacity.

The file buffer remains valid across retransmissions and reauthentication. Normal
and ordinary early-exit cleanup clear its full allocation and release its nodes.
The temporary decoded stack buffer is cleared on all encoder exits. The existing
message-owner cleanup clears each RADIUS message buffer; queue ownership and
legacy callers are unchanged. Remove the file after the owned process exits.
The signal/abort/host-failure cleanup limits in the secret-input section also apply.

### Legacy `-N`

Legacy `-N ATTRIBUTE_ID:SYNTAX:VALUE` remains available outside the application.
Its parser is not a validation boundary:

| Syntax | Upstream behavior |
| --- | --- |
| `s` | String; silently truncates to the attribute buffer |
| `d` | `atoi` followed by a network-order 32-bit integer |
| `x` | Even-length hex, optional `0x` prefix, at most 253 decoded bytes |
| Bare attribute ID | One NUL byte, not a zero-length value |

Legacy `-N` retains extended-aware construction for IDs 241 through 246 rather
than the protected file's raw opaque semantics. The existing long-extended
fragment copy now uses the fragment length, preserving exact reassembly instead
of copying all remaining bytes into each fragment. Neither interface removes the
legacy `-s` or `-S` options.

## Diagnostics and result evidence

In `-F` mode, the patch sets `wpa_debug_show_keys=0` and `MSG_INFO` before reading
configuration or initializing EAP. It also disables RADIUS packet dumps and
omits credential values from the demonstrated network-parser error sites. This
suppresses the known debug-level password, challenge-response, TLS-secret, PMK,
and MPPE-key dumps in the selected code paths. Certificate subjects and other
server diagnostics are still untrusted; filter them before storage or display.
Legacy invocation retains upstream diagnostic behavior and must not be used by
the application.

After all input-derived diagnostics, normal completion emits these lines in this
order:

```text
MPPE keys OK: INTEGER  mismatch: INTEGER
EAPOL_TEST_RESULT accept=INTEGER reject=INTEGER timeout=INTEGER mppe_ok=INTEGER mppe_mismatch=INTEGER cert_error=INTEGER
SUCCESS_OR_FAILURE
```

`SUCCESS_OR_FAILURE` is exactly `SUCCESS` or `FAILURE`, not that placeholder.
Use the anchored final footer immediately before that terminal line, not any
matching text in earlier diagnostics. Derive **every** footer fact only after a
normal, consistent completion: exit status 0 with `SUCCESS`, or a positive Unix
exit status with `FAILURE`. A negative subprocess return code means a signal,
not a normal failure. Reject the whole footer for signals, inconsistent terminal
status, malformed fields, or out-of-domain values. Cancellation and the overall
deadline retain precedence over all child evidence. Record Access-Accept
separately from peer and MPPE-key success. Early argument/configuration errors
can omit the footer; missing evidence never means success or a passing negative
expectation.

The field order and native domains are fixed:

| Field | Native representation | Valid domain |
| --- | --- | --- |
| `accept`, `reject`, `timeout` | `int` flags | 0 or 1 |
| `mppe_ok`, `mppe_mismatch` | Existing signed `int` counters | 0 through 2147483647 |
| `cert_error` | Saturating `u32` counter | 0 through 4294967295 |

The MPPE domains describe the packaged Debian target, not Boolean flags. Do not
add unsupported cross-field assumptions from a diagnostic string or exit code.

The accept/reject counters are set after RADIUS integrity validation. In `-F`
mode, a no-EAP Access-Reject without Message-Authenticator still needs a valid
Response Authenticator. Valid legacy rejections remain supported. Invalid or
spoofed replies do not set either counter. Do not classify the raw upstream
Access-Accept/Reject packet-dump text as authenticated evidence.

`cert_error` counts only the typed `TLS_CERT_CHAIN_FAILURE` event, through an
optional native EAP/EAPOL callback. It includes every reason, including
`UNSPECIFIED`. Peer certificate metadata, generic TLS alerts, and server rejection
of the client certificate do not increment it. Server SAN values can contain
newlines and forge a `CTRL-EVENT-EAP-TLS-CERT-ERROR` line, so no diagnostic prefix
establishes certificate-error evidence. A valid final footer with `cert_error>0`
is the certificate-validation fact. Its counter saturates rather than wrapping.
A valid footer's `timeout=1` is a timeout fact, not server rejection.

Unix return values are the low eight bits of upstream's signed result: timeout
can be 254, rejection 253, and MPPE mismatch 252. MPPE mismatch can overwrite a
rejection or timeout return code. A protected request preparation failure forces
`ret=-1` (Unix status 255) after MPPE selection, even with legacy `-n`; it cannot
become success merely because key checking is disabled. Use verified footer
fields with the final status, not the exit code alone, to classify the outcome.

## Runtime tests

Run `python runtime/tests/check_runtime.py --binary /path/to/eapol_test` after
building. The test runner requires a real binary; an absent binary is an error,
not a passing skip. It uses generated private credentials, ephemeral TLS material,
and loopback-only UDP fixtures. It never puts a credential value in arguments,
environment variables, test source, or failure messages.

The tests cover protected input failures, exact 4096-byte and CR/LF-bearing
secret use in request and response authenticators, hex credentials,
raw protected attribute encoding and boundaries, legacy extended fragmentation,
maximum ASCII and four-byte UTF-8 credentials, all four method ClientHello starts,
typed certificate-error evidence, a signed malicious newline SAN, generic TLS
alerts, valid/forged RADIUS replies, timeouts, canned-accept rejection, and
preservation of `-S`. These are runtime boundary tests, not proof of successful
inner authentication. Complete EAP authentication requires the separately
managed integration server and the application's actual execution path.
