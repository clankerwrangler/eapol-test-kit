# Implementation contract

This document defines the behavior and security requirements that maintainers
and contributors are expected to preserve. It is not a record of completed
verification. See the [README](../README.md) for setup and usage, and
[runtime verification](../runtime/VERIFICATION.md) for test evidence and its
limitations.

When behavior changes, update the relevant requirements and tests together.
Optional extensions are identified below; they are not existing features or
requirements to implement them.

## Scope and runtime

EAPOL Test Kit provides a web interface for running `eapol_test` against a
separate RADIUS server. The deployment target is Docker on Debian. FreeRADIUS
is not bundled with the application image or its Compose deployment; integration
tests use separately managed server infrastructure.

The application uses Python 3.12, FastAPI, SQLite, `cryptography`, and static
HTML, CSS, and JavaScript. It requires no frontend build, external CDN, Redis,
Docker socket, privileged container, or host networking.

| Setting | Value or default |
| --- | --- |
| ASGI application | `eapolkit.app:app` |
| Application port | `8080` |
| Data directory | `EAPOLKIT_DATA_DIR`, default `/data` |
| Client executable | `EAPOLKIT_BINARY`, default `/usr/local/bin/eapol_test` |

Only one authentication run may be active at a time. The HTTP API must remain
responsive while it runs. Restarting the application must not replay an
unfinished authentication attempt.

## API conventions

API routes use JSON unless an endpoint explicitly accepts a multipart upload or
returns a file. Run exports are JSON downloads. Certificate and PFX downloads
return the corresponding file format.

Object IDs are opaque strings. Object responses contain the public fields
directly, without an additional envelope; collection responses are JSON arrays.
Internal storage fields are not part of the API.

Errors use a safe `detail` string or validation entries containing `loc`, `msg`,
and `type`. Validation responses must not echo submitted secrets or raw input
values.

Passwords and RADIUS shared secrets are write-only. An ordinary object response
must not contain saved passwords, shared secrets, private keys, master keys, or
session tokens. Presence flags such as `has_password` and `has_secret` indicate
whether credentials are saved. Private-key export is a separate, explicit
operation described below.

When updating a write-only credential, omitting the field preserves its saved
value. Supplying a nonempty value replaces it. An explicitly empty or `null`
credential is invalid. The UI leaves saved credential inputs blank and omits
unchanged credentials from update requests.

These preservation rules also apply to extra attributes as specified below.
They do not make every omitted field in a `PUT` request a partial update;
other fields follow their input schema and defaults.

## Authentication and deployment

### Sessions

| Endpoint | Request and response |
| --- | --- |
| `GET /api/session` | Returns `{setup_required, authenticated, csrf_token}`. |
| `POST /api/setup` | Accepts `{password}` and returns the session shape. Available only before initialization. |
| `POST /api/login` | Accepts `{password}` and returns the session shape. |
| `POST /api/logout` | Ends the session and clears its cookie. |
| `GET /api/status` | Returns `{version, eapol_test_available, active_run_id}`. |

The CSRF token is available only to an authenticated session. Session tokens
travel in an `HttpOnly` cookie with `SameSite=Strict`, not in object responses.

Browser requests that change state require `X-EapolKit-Request: 1`.
Authenticated mutations also require `X-CSRF-Token`. Reject foreign origins and
unexpected HTTP hosts. Do not enable cross-origin API access through CORS.
Tests may explicitly add `testserver` to their allowed hosts without changing
the deployment defaults.

### Password initialization

The default deployment exposes the UI only on localhost and permits first-run
web setup. Terminal setup provides an alternative for hosts without a local
browser:

```sh
docker compose build &&
docker compose run --rm --no-deps kit python -m eapolkit.setup &&
docker compose up -d
```

The setup command uses the application image, non-root entrypoint, and named
data volume. It must not start the web service or publish ports. It asks for
the password twice in an interactive terminal, with input hidden.

Terminal and web setup use the same password validation and initialization
path. Saving the password hash is an atomic insert-if-absent operation: neither
path may replace an existing password, including when setup requests race.

The terminal reader accepts 1 to 4096 UTF-8 characters without imposing the
kernel's canonical-line length limit. It must reject malformed UTF-8 and
overlength entries as a whole, never initialize a password from a truncated
prefix, and keep invalid input hidden until the unquoted line ends. It requires
an interactive terminal and must not fall back to echoed input or accept the
password through command-line arguments, environment variables, or redirected
input. Status messages must not include password content.

A setup failure stops the documented `&&` sequence. This command sequence is
not a global startup gate and does not disable first-run web setup.

### Network exposure

`EAPOLKIT_BIND_ADDRESS` selects a host address for opt-in HTTP access. Compose
passes the same value to the application so a concrete bind IP is also accepted
as an HTTP host. The operator must already have that address configured.

Without an override, allowed hosts are `localhost`, `127.0.0.1`, `::1`, and any
concrete IP supplied through `EAPOLKIT_BIND_ADDRESS`. Wildcard binds such as
`0.0.0.0` and `::` do not allow additional HTTP hosts. A nonempty
`EAPOLKIT_ALLOWED_HOSTS` replaces the defaults rather than extending them;
include `127.0.0.1` for the container health check.

Direct HTTP access does not encrypt passwords, session cookies, credentials,
or uploaded private material. Deployment documentation must state this and
prohibit exposing the HTTP endpoint to the public internet. SSH tunneling and
HTTPS reverse-proxy access remain supported deployment options. HTTPS
deployments use `EAPOLKIT_SECURE_COOKIES=1`.

Changing the bind address must not disable host, origin, CSRF, or cookie
protections. The application does not provision host addresses, firewall rules,
HTTPS certificates, or a reverse proxy.

## RADIUS targets

Targets describe how to reach a RADIUS server. Profiles, defined below, describe
the authentication attempt. They are saved independently.

Use `GET` and `POST /api/targets` to list and create targets, and `PUT` or
`DELETE /api/targets/{id}` to update or remove them.

| Field | Meaning |
| --- | --- |
| `id` | Server-assigned object ID. |
| `name` | Display name. |
| `host` | Server DNS name or IP literal. |
| `port` | UDP destination port; default `1812`. |
| `timeout_seconds` | Overall run timeout; default `30`, range `5` to `120`. |
| `nas_identifier` | NAS-Identifier; default `eapol-test-kit`. |
| `nas_ip_address` | Optional IPv4 NAS-IP-Address attribute. |
| `secret` | Write-only RADIUS shared secret. |
| `has_secret` | Response flag indicating whether a secret is saved. |

Shared secrets contain 1 to 4096 UTF-8 **bytes**, not characters. Reject NUL,
but preserve all other bytes, including CR, LF, and leading or trailing
whitespace. Do not trim or normalize the value. The protected native input must
use exactly the same bytes and limits.

`NAS-IP-Address` is a RADIUS attribute, not a source-address selector. The server
must recognize the packet's actual source address and shared secret. Changing
the NAS attribute does not change the UDP source address.

## Profiles and presets

`GET /api/presets` returns editable starting profiles for `eap-tls`,
`peap-mschapv2`, `ttls-pap`, and `ttls-mschapv2`.

Use `GET` and `POST /api/profiles` to list and create profiles, and `PUT` or
`DELETE /api/profiles/{id}` to update or remove them.

| Field | Meaning or default |
| --- | --- |
| `id` | Server-assigned object ID. |
| `name` | Display name. |
| `method` | One of the four preset method names. |
| `identity` | EAP identity. |
| `anonymous_identity` | Optional outer identity. |
| `ca_certificate_id` | Saved certificate asset used to verify the server. |
| `client_identity_id` | Optional saved client certificate and private key. |
| `server_name` | Expected server certificate name. |
| `tls_min_version` | `1.2` or `1.3`; default `1.2`. |
| `tls_max_version` | `auto`, `1.2`, or `1.3`; default `auto`. |
| `fragment_size` | EAP fragment size; default `1398`. |
| `calling_station_id` | Calling-Station-Id attribute. |
| `extra_attributes` | Additional RADIUS attributes, as specified below. |
| `allow_expired_client_certificate` | Whether local validation permits an expired client certificate; default `false`. |
| `password` | Write-only EAP password. |
| `has_password` | Response flag indicating whether a password is saved. |

Calling-Station-Id and extra attributes belong to the profile, not the target.
A profile may be saved before it has everything needed to run. Execution must
validate the required identity, credentials, certificates, server CA, and
expected server name before launching the client.

`POST /api/profiles/{id}/duplicate` accepts an optional `{name}` and returns a
new profile with its own ID. It retains the source profile's saved password on
the server and references the same certificate assets. The password must not
make a round trip through the browser.

`GET /api/profiles/{id}/preview` returns `{configuration, warnings}`. The
preview follows the generated configuration, with secrets redacted and
certificate references substituted for private filesystem paths.

Profiles are configured through the supported fields and their preview, not by
uploading arbitrary wpa configuration. Web input must not select arbitrary
paths, directives, plugins, engines, or modules. Allowing an expired client
certificate must not disable server-certificate time checks.

### Extra RADIUS attributes

Each row identifies a RADIUS attribute and its encoding:

| Field | Meaning |
| --- | --- |
| `id` | RADIUS attribute type, from `1` to `255`; not the row's object identity. |
| `type` | `string`, `integer`, `hex`, or `ipaddr`. |
| `key` | Opaque, stable row key assigned by the server. |
| `sensitivity` | `public` or `private`. |
| `value` | Supplied value; returned only for public rows. |
| `has_value` | Response flag indicating whether the row has a saved value. |

Validate text, unsigned integers, hexadecimal bytes, and IPv4 addresses before
encoding them. Hex input contains the attribute payload, without its outer
RADIUS type/length header. Native payload and total-file limits still apply.

A new row supplies `value` and omits `key`. Every stored value is encrypted in
one canonical per-row representation, including values classified as public.
Public rows expose their value on reads; private rows do not.

#### Updates and visibility

An omitted value preserves the saved value only when the row key belongs to the
same profile. Reject unknown keys, duplicate keys within an update, keys from
another profile, and changes to the attribute ID or encoding without a
replacement value.

Omitting `extra_attributes` preserves the saved list. Supplying an empty list
removes every extra row.

Known credential-bearing attributes must remain private. An explicit request
to classify one as public returns HTTP 422 rather than silently changing the
request. New vendor-specific attributes of type `26` and extended containers
`241` through `246` default to private. Their payloads remain usable as opaque
bytes; the application must not invent a nested schema or reject all such
containers.

Making a private row public requires an explicit `sensitivity=public`, a newly
supplied value, and UI confirmation. The same requirements apply when first
classifying an opaque container as public. Changing metadata alone must never
reveal a saved private value.

An unchanged public row may preserve its value without repeated confirmation,
including a previously classified public container. A public-to-private change
may also preserve the existing value. If an ID or encoding changes with a
replacement value and no sensitivity is supplied, use the new attribute's
default without implicitly changing a private row to public. Otherwise,
unchanged rows retain their classification.

The UI must distinguish a saved hidden value from a missing value and must not
carry an old public selection into a newly classified opaque payload without
confirmation.

#### Migration and execution

Migration preserves the readable public classification of recognized legacy
plaintext rows, including historically readable opaque containers. It must not
expose a row that was already private, reinterpret an unknown record schema,
or make a known credential-bearing attribute public. Compatibility with legacy
records does not add extra attributes to the target input API.

All generated and custom attributes reach the native client through the
protected attribute-file interface in
[runtime/INTERFACE.md](../runtime/INTERFACE.md). Attribute values must not appear
in process arguments. Legacy `-N` remains available outside the web application.

Private values and their encoded forms must be included in diagnostic
redaction and excluded from previews, run snapshots, and reports.

## Certificates

Certificate assets have one of four kinds: `trust`, `identity`, `ca`, or `csr`.
The UI and API must distinguish server trust from client identity and issuer
trust. Creating a lab CA does not configure the RADIUS server to trust it.

### Metadata

`GET /api/certificates` returns metadata objects with these fields:

```text
id, name, kind, subject, issuer, not_before, not_after,
fingerprint_sha256, key_type, san_dns, san_email, san_uri,
eku, has_private_key, warnings
```

Validity timestamps use ISO 8601 UTC or `null` where inapplicable. CSRs may have
`null` issuer and fingerprint fields. Subject and issuer use readable
distinguished names. SANs, EKUs, and warnings are arrays, empty when absent.
EKUs use names such as `clientAuth` and `serverAuth`, or an OID for an
unrecognized usage. Key types use labels such as `rsa3072` or `ec-p256`;
imported algorithms may have other labels.

### Import and generation

`POST /api/certificates/import` accepts multipart fields `name`, `kind`,
`certificate`, `private_key`, `pfx`, and `passphrase`. Import kinds are `trust`
and `identity`. The required file combination depends on the kind and format:
trust imports accept PEM CA chains; identity imports accept a certificate with
its matching private key or a PKCS#12/PFX bundle. Enforce upload limits, verify
key matching, and discard import passphrases after use.

Generation endpoints accept JSON:

| Endpoint | Fields |
| --- | --- |
| `POST /api/certificates/generate-ca` | `name`, `common_name`, `days`, `key_type` |
| `POST /api/certificates/generate-client` | `issuer_id`, `name`, `common_name`, `days`, `key_type`, `san_dns`, `san_email`, `san_uri` |
| `POST /api/certificates/generate-csr` | `name`, `common_name`, `key_type`, `san_dns`, `san_email`, `san_uri` |

Supported generation key types are `rsa2048`, `rsa3072`, and `ec-p256`, with
`rsa3072` as the default. Default validity is 3650 days for a CA and 365 days
for a client certificate. A client certificate must not outlive its issuer.
Generated certificates require the appropriate basic constraints and, for
clients, `clientAuth` usage.

CSR generation keeps the private key protected in the saved request.
`POST /api/certificates/{id}/complete` accepts the signed certificate as a
multipart `certificate` field. It must verify that the certificate matches
the saved key before converting the request into a client identity.

### Export and deletion

`GET /api/certificates/{id}/download?format=certificate|csr` returns only public
material. Private keys must not be exported by a GET request.

`POST /api/certificates/{id}/export-pfx` accepts `{passphrase}` and returns a
protected PFX containing the private identity. Export requires a passphrase of
at least eight characters and explicit confirmation in the UI.

`DELETE /api/certificates/{id}` must refuse to remove an asset referenced by a
saved profile.

## Authentication runs

### Endpoints and lifecycle

| Endpoint | Behavior |
| --- | --- |
| `POST /api/runs` | Accepts `{target_id, profile_id}` and returns a run record. |
| `GET /api/runs?limit=50` | Returns recent records; maximum requested limit is `100`. |
| `GET /api/runs/{id}?after=0` | Returns run details and log entries after the given sequence. |
| `POST /api/runs/{id}/cancel` | Cancels that run if it is the application's active run. |
| `GET /api/runs/{id}/export` | Downloads a sanitized JSON report. |
| `DELETE /api/runs/{id}` | Removes a terminal run record; queued or running records cannot be deleted. |

Reject a second active run with HTTP 409. Validate the target and profile before
launch. The overall deadline includes preparation, including DNS resolution,
not just time spent in `eapol_test`.

Cancellation and timeout must terminate and reap the process group owned by
that run. On startup, mark unfinished records as interrupted rather than
resubmitting them. The UI obtains live logs by polling once per second while a
run is active; WebSockets are not required.

### Records

Core record fields are:

```text
id, target_id, profile_id, target_name, profile_name,
status, outcome, summary, created_at, started_at, finished_at,
duration_seconds, exit_code
```

Timestamps use ISO 8601 UTC. Events that have not happened yet have `null`
timestamps. Outcome, duration, and exit code remain `null` while unknown.

Run status is one of `queued`, `running`, `completed`, `cancelled`, or
`interrupted`. Outcome is one of `accept`, `reject`, `certificate_error`,
`timeout`, `configuration_error`, `cancelled`, `interrupted`, or `error`.
A completed run is not necessarily a successful authentication.

Result evidence is exposed separately through `radius_response` (`accept`,
`reject`, or `null`), `peer_success` (boolean or `null`), and
`mppe_keys_match` (boolean or `null`). Unknown facts remain `null`.

Details include `snapshot` with `target`, `profile`, and redacted
`configuration`, plus `log_lines`, `next_seq`, and `truncated`. Log entries have
`{seq, line}` fields. Snapshots use the same secret-free target and profile
shapes as ordinary API responses, with diagnostic redaction also applied.

`returned_attributes` is reserved for safe `{name, value}` entries. The current
runner leaves this array empty. Collecting returned authorization attributes
is an optional extension, not a guaranteed feature. Any future parser must
exclude MPPE keys and other credential-bearing values.

### Outcome evidence

Classify results from the native completion footer defined in
[runtime/INTERFACE.md](../runtime/INTERFACE.md), immediately before the final
`SUCCESS` or `FAILURE` line. Accept the footer only after normal completion
with a consistent exit status, exact syntax, and values within the documented
native domains.

An `accept` result requires authenticated Access-Accept, successful EAP peer
completion, and matching MPPE keying material, without rejection, timeout, or
certificate-validation errors. Access-Accept alone is insufficient.

For a normally completed failure, native timeout evidence takes precedence,
then certificate-validation evidence, then authenticated Access-Reject.
A rejection must be observed, not inferred from a timeout, launch failure,
or unrelated TLS error. Server-side policy reasons must not be guessed.

The native `cert_error` counter records certificate-validation callbacks.
Certificate subjects, SAN values, generic TLS alerts, and arbitrary diagnostic
lines are not equivalent evidence. Even text resembling a certificate-error
event must not establish the result. A server rejecting a client certificate
is not, by itself, evidence that this client's server-certificate validation
failed.

Reject the footer as evidence after a signal, malformed or missing footer, or
inconsistent terminal status. Application cancellation and the overall deadline
take precedence over child output. Missing evidence must never become an
accept, rejection, or certificate-error result by default.

### Outcomes and verdicts

The public run API reports what happened. It does not accept an expected result
or expose a pass/fail verdict field.

The standalone `verdict(expected, outcome)` helper in `runner.py` is separate
from that API. When used to compare a supported authentication expectation
(`accept`, `reject`, or `certificate_error`), a matching outcome is `pass`, a
different authentication outcome is `fail`, and an operational failure is
`inconclusive`. This helper does not make a missing result into a successful
negative test or imply that expectation selection exists in the UI.

## Storage and execution security

### Stored data and keys

Reusable credentials, private keys, and all extra-attribute values must be
encrypted with a per-installation master key. The web UI password is stored as
a password hash, not as a reusable encrypted credential.

The current key location is `<data_dir>/secrets/master.key`, normally
`/data/secrets/master.key`. Keep the secrets directory at mode `0700`, the key
at `0600`, and all other application data private. The master key must not
appear in source, logs, process arguments, or exported database snapshots.

A missing key for an existing encrypted database is an error. Do not silently
create a replacement. An invalid key or a key that does not match the database
must also fail rather than creating an alternate installation state.

There is no separate configuration setting for an alternative key path.
External key-path configuration is an optional extension. If added, an invalid
or unavailable explicitly configured key must cause failure without falling
back to another key.

Host administrators remain trusted. Encryption does not protect a stolen
backup that contains both the encrypted data and its master key. Deployment
and backup documentation must make that limitation clear.

### Client execution

Each run uses a private temporary directory and private files for its
configuration, certificates, private key, shared secret, and attributes.
The client receives the shared secret through protected `-F` input and
attributes through protected `-G` input, not through value-bearing `-s` or
`-N` arguments. The native file checks and limits are defined in
[runtime/INTERFACE.md](../runtime/INTERFACE.md).

Launch the client with an argument array, without a shell. Encode identities
and passwords using the supported wpa configuration format rather than raw
string interpolation or arbitrary restrictions on password characters.
Hex encoding is reversible and does not make the generated configuration safe
to publish. User input must not select arbitrary files, engines, or modules.

Enforce the overall deadline, terminate and reap owned processes on timeout or
cancellation, and remove run-owned files after every handled outcome. Startup
cleanup must be limited to abandoned run directories owned by this installation.
A cleanup failure must be reported rather than silently treated as success.

### Logs, previews, and limits

Sanitize diagnostics before saving or returning them. Redaction must cover
supplied secrets and their encoded forms. Suppress private-key material,
credential-bearing RADIUS values, and key or challenge-response dumps. The
application must not enable `eapol_test` key-material debugging or ordinary
request-body logging.

Apply limits to uploads, requests, individual log lines, total stored log
volume, and retained history. Application defaults are defined in
[settings.py](../src/eapolkit/settings.py); native input bounds are defined in
the runtime interface. Exceeding a limit must not expose a secret or turn
truncated data into valid input.

## Testing and verification

Tests must cover authentication and CSRF boundaries, shared password
initialization, credential preservation, encryption and redaction, extra-
attribute validation and visibility changes, certificate key matching and
signing, and command or configuration injection.

Run tests must cover cancellation, preparation-inclusive deadlines, process
cleanup, interrupted-run recovery, and result classification. Evidence tests
must include malformed or missing footers, spoofed diagnostic text, certificate
metadata containing event-like text, and separation of RADIUS responses from
EAP and MPPE success.

Native boundary tests and full authentication tests prove different things.
Tests using mocked processes or loopback UDP fixtures are not evidence of
successful end-to-end EAP authentication. Real integration tests use a separate
RADIUS server and the application's actual execution path. An unavailable
server or skipped test must never be reported as a successful authentication.

The same distinction applies to deployment checks: a loopback-alias test can
verify bind-address and allowed-host handling, but it does not prove
reachability from another machine. Claims about LAN access require a test over
that network path.

Record the environment, image or binary tested, results, and limitations in
[runtime/VERIFICATION.md](../runtime/VERIFICATION.md). Requirements in this file
are not a substitute for that evidence.
