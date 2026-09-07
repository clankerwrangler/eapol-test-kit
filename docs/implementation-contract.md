# Implementation contract

## Scope

Build a personal eapol_test web workbench for Docker on Debian. Do not include FreeRADIUS in the image, Compose file, or deliverable. Integration fixtures are separate infrastructure.

Use Python 3.12, FastAPI, SQLite, cryptography, and a static HTML/CSS/JavaScript UI. No frontend build, external CDN, Redis, Docker socket, privileged mode, or host networking. App import: `eapolkit.app:app`. App port: 8080. Data: `EAPOLKIT_DATA_DIR`, default `/data`. Binary: `EAPOLKIT_BINARY`, default `/usr/local/bin/eapol_test`. One active run. Keep HTTP handling responsive during a run. Mark unfinished records interrupted at startup; never replay authentication automatically.

## API conventions

All `/api/` routes use JSON except certificate import/download. IDs are opaque strings. Errors expose a safe `detail` string or standard FastAPI validation details. Return stored objects directly, and return lists as JSON arrays. Never return stored passwords, RADIUS secrets, private keys, master keys, or session tokens in ordinary object responses. A supplied write-only secret replaces the saved value; an omitted secret preserves it. Empty secrets are invalid. UI input remains blank when editing a saved secret.

`GET /api/session` returns `{setup_required, authenticated, csrf_token}`. The CSRF token is available only for an authenticated session. `POST /api/setup` and `POST /api/login` accept `{password}` and return the same session shape. `POST /api/logout` clears the session. All browser mutations include `X-EapolKit-Request: 1`; authenticated mutations also include `X-CSRF-Token`. Reject foreign origins and unexpected hosts. Use a strict HttpOnly session cookie. No CORS. Setup is available only before a password exists. Password initialization uses one atomic insert-if-absent operation shared by terminal and web setup; neither path can replace an existing password. Tests can construct settings with `testserver` explicitly allowed.

### Deployment and initial password

Default host publication is localhost only. First-run web setup remains available. For a CLI-only Debian host, use `docker compose run --rm --no-deps kit python -m eapolkit.setup` after building the image and before starting network publication. The command runs through the same image, non-root entrypoint, and named data volume as the web service, without starting the app or publishing service ports. It uses two non-echoing terminal prompts, the existing `PasswordInput` validation, and the shared `Auth`/`Store` password path. Require an interactive terminal and reject password echo fallback. Do not accept passwords through arguments, environment variables, or redirected input. The terminal reader accepts 1 to 4096 UTF-8 characters without the kernel canonical-line limit. Overlength and malformed UTF-8 entries stay unechoed until the unquoted line ends and never initialize a password prefix. Report only fixed secret-free status messages. Setup failure stops the documented `&&` deployment sequence; this does not add a global startup gate or remove web setup.

Set only `EAPOLKIT_BIND_ADDRESS` in `.env` to select a concrete IP for opt-in HTTP publication. Compose passes the same value to the app so its default allowed hosts include that IP plus `localhost`, `127.0.0.1`, and `::1`. A nonempty `EAPOLKIT_ALLOWED_HOSTS` remains an authoritative override. Wildcard bind addresses do not expand accepted HTTP hosts. Preserve host, same-origin, CSRF, HttpOnly, and SameSite checks.

Opt-in HTTP on that address does not encrypt passwords, session cookies, credentials, or private material in transit. State this limitation in deployment guidance and prohibit public-internet publication. Keep SSH tunnel and HTTPS reverse-proxy options; use `EAPOLKIT_SECURE_COOKIES=1` for HTTPS deployment. The kit does not provision host addresses, firewalls, certificates, or a proxy. A checked Compose path may use a loopback alias to verify bind-address host acceptance; that is not a second-host LAN reachability test. A browser on another computer can be used only if the operator's network already reaches the published address.

`GET /api/status` returns `{version, eapol_test_available, active_run_id}`.

## Targets

`GET/POST /api/targets`, `PUT/DELETE /api/targets/{id}`.

Fields: `id`, `name`, `host`, `port` (1812), `timeout_seconds` (30, range 5 to 120), `nas_identifier` (`eapol-test-kit`), and optional `nas_ip_address`. Attribute types are `string`, `integer`, `hex`, and `ipaddr`; validate them before encoding them for protected runtime input. `secret` is write-only and contains 1 to 4096 UTF-8 bytes. Reject NUL, and preserve every other byte, including CR/LF and leading or trailing whitespace. Do not trim or normalize it. The protected runtime input uses the same byte contract. Reads include `has_secret`. The target host supports IP literals and DNS names. NAS-IP-Address is an attribute, not packet source selection.

### Extra attribute rows

Each row has `id` (RADIUS type 1 through 255), `type`, an opaque stable server-assigned `key`, `sensitivity` (`public` or `private`), and `has_value` on reads. A new input row omits `key` and supplies `value`. Public reads include `value`; private reads omit it. Encrypt every stored extra-attribute value in one canonical per-row representation. During migration, recognized legacy plaintext rows that were historically readable retain their public classification and readable values, including opaque containers. This migration rule does not expose an already private value or reinterpret an unknown record schema; known credential-bearing IDs remain private.

On update, an omitted `value` preserves the value for a matching row key in that profile. Reject unknown or duplicate keys, cross-profile keys, and omitted-value changes to the RADIUS ID or encoding. Omission of the entire list preserves it; an explicit empty list removes all extra rows. Known credential-bearing attributes are always private. Reject an explicit public classification for those IDs with HTTP 422 rather than silently coercing it. New vendor-specific type 26 and extended containers 241 through 246 default to private, but remain usable. Do not guess vendor-specific nested layouts or reject every container type.

Public classification of an opaque container, or a private-to-public transition, requires explicit `sensitivity=public` with a newly supplied value and UI confirmation. Never reveal a stored private value by changing metadata. An unchanged public row can preserve its value without repeated confirmation, including a previously classified public container. Public-to-private can preserve the existing value. If an ID or encoding changes with a replacement and sensitivity is omitted, apply the new attribute default, but never implicitly change a private row to public. Unchanged rows preserve their classification. The UI distinguishes a saved hidden value from an empty or absent value and does not silently carry a public selection into a newly classified opaque payload.

Pass every generated and extra attribute through the protected native attribute-file interface in `runtime/INTERFACE.md`, not a value in process arguments. Preserve legacy CLI `-N` outside the web app. Apply native payload and total-file bounds. Include private values and their encoded forms in diagnostic redaction; exclude them from previews, run snapshots, and reports.

## Profiles and presets

`GET /api/presets` returns four editable starting profiles. Method names are `eap-tls`, `peap-mschapv2`, `ttls-pap`, and `ttls-mschapv2`.

`GET/POST /api/profiles`, `PUT/DELETE /api/profiles/{id}`.

`POST /api/profiles/{id}/duplicate` accepts optional `{name}` and returns a new profile. Preserve the encrypted saved password on the server without returning it to the browser. The new record has its own ID and references the same selected certificate assets.

Fields: `id`, `name`, `method`, `identity`, optional `anonymous_identity`, `ca_certificate_id`, optional `client_identity_id`, `server_name`, `tls_min_version` (`1.2` or `1.3`), `tls_max_version` (`auto`, `1.2`, or `1.3`), `fragment_size` (1398), `calling_station_id`, `extra_attributes`, and `allow_expired_client_certificate` (false). `password` is write-only; reads include `has_password`. Calling-Station-Id and extra RADIUS attributes belong to the profile. Extra-attribute rows use the same encoding, privacy, and key-preservation rules previously defined for target extra attributes. A recipe can be saved before it is runnable; validate all required credentials/trust assets before execution. Require explicit server CA and expected server name.

`GET /api/profiles/{id}/preview` returns `{configuration, warnings}`. Redact secrets and use asset references instead of private filesystem paths. The UI supports profile duplication. Editable advanced fields and an exact generated preview are the first version's configuration interface; do not execute arbitrary uploaded wpa configuration directives, plugins, engines, or filesystem paths.

## Certificates

`GET /api/certificates` returns metadata objects. Kinds are `trust`, `identity`, `ca`, and `csr`. Exact fields are `id`, `name`, `kind`, `subject`, `issuer`, `not_before`, `not_after`, `fingerprint_sha256`, `key_type`, `san_dns`, `san_email`, `san_uri`, `eku`, `has_private_key`, and `warnings`. Validity dates are ISO 8601 UTC strings or null. Issuer and fingerprint can be null for a CSR. Subject and issuer use readable distinguished-name strings. SANs, EKUs, and warnings are arrays of strings; use empty arrays when absent. EKUs use readable values such as `clientAuth` and `serverAuth`, or an OID string for an unrecognized usage. `key_type` is a readable machine label such as `rsa3072` or `ec-p256`; imported algorithms can have other labels.

`POST /api/certificates/import` uses multipart fields `name`, `kind` (`trust` or `identity`), optional `certificate`, optional `private_key`, optional `pfx`, and optional `passphrase`. Trust imports accept PEM chains. Identity imports accept PEM certificate plus key, or PKCS#12/PFX. Verify that the key matches. Bound uploads and discard import passphrases after use.

`POST /api/certificates/generate-ca` accepts `{name, common_name, days, key_type}`.
`POST /api/certificates/generate-client` accepts `{issuer_id, name, common_name, days, key_type, san_dns, san_email, san_uri}`.
`POST /api/certificates/generate-csr` accepts `{name, common_name, key_type, san_dns, san_email, san_uri}`.
Key types: `rsa2048`, `rsa3072`, and `ec-p256`. Default `rsa3072`. Default validity: CA 3650 days, client 365 days; never issue a client beyond issuer validity. Apply correct basic constraints and clientAuth usage. CSR generation retains the protected key for completion.

`POST /api/certificates/{id}/complete` accepts multipart `certificate` for a CSR and verifies key matching before producing an identity.
`GET /api/certificates/{id}/download?format=certificate|csr` exports public material.
`POST /api/certificates/{id}/export-pfx` accepts `{passphrase}` and explicitly exports a protected private identity. Require a nonempty export passphrase of at least eight characters and an explicit UI confirmation. Do not export private material on GET.
`DELETE /api/certificates/{id}` refuses deletion when a saved profile references the asset. Public downloads and labels must distinguish server trust from client issuer trust. Generating a CA does not configure FreeRADIUS to trust it.

## Runs

`POST /api/runs` accepts `{target_id, profile_id}` and returns a run record with an ID. Refuse a second active run with HTTP 409. Validate inputs before launch. `GET /api/runs?limit=50` returns recent records (maximum 100). `GET /api/runs/{id}?after=0` returns the record, safe profile/target snapshot, `log_lines` as `{seq, line}` objects after the requested sequence, `next_seq`, and `truncated`. UI polling once per second during an active run provides live logs without WebSockets. `POST /api/runs/{id}/cancel` cancels only that owned run. `GET /api/runs/{id}/export` downloads sanitized JSON. `DELETE /api/runs/{id}` removes only a completed record.

Run record fields are `id`, `target_id`, `profile_id`, `target_name`, `profile_name`, `status`, `outcome`, `summary`, `created_at`, `started_at`, `finished_at`, `duration_seconds`, and `exit_code`. Timestamps are ISO 8601 UTC strings; timestamps not yet reached, outcome, duration, and exit code are null when unknown. The UI reports the observed outcome; it does not require a pre-selected pass/fail assertion. Run detail adds `snapshot` with `target`, `profile`, and redacted `configuration` members, plus `log_lines`, `next_seq`, and `truncated`. Target/profile snapshots use the same secret-free shapes as their read APIs.

Run states: `queued`, `running`, `completed`, `cancelled`, and `interrupted`. Outcomes: `accept`, `reject`, `certificate_error`, `timeout`, `configuration_error`, `cancelled`, `interrupted`, or `error`. Verdicts: `pass`, `fail`, or `inconclusive`. Detail also exposes `radius_response` (`accept`, `reject`, or null), `peer_success` (boolean or null), and `mppe_keys_match` (boolean or null) when parser evidence supports them. Use null rather than guessing. `returned_attributes` is an array of safe `{name, value}` objects, empty when uncollected. Record Access-Accept separately from overall peer/keying success where possible. An explicit observed rejection can meet `reject`; a timeout, launch error, or unrelated TLS failure cannot. Certificate-error expectations require corresponding evidence. Do not guess server-side policy rejection reasons. Returned RADIUS attributes are optional if reliable safe parsing is not ready; never expose MPPE keys or other credential-bearing attributes.

Result evidence comes from the native completion footer specified in `runtime/INTERFACE.md`, immediately before the exact final `SUCCESS` or `FAILURE` line. The native `cert_error` counter records actual certificate-validation error callbacks. Certificate subjects, SAN values, and arbitrary diagnostic lines never establish a certificate-error result, even if they contain an event prefix. Missing or malformed final evidence, a signaled process, cancellation, and the overall deadline cannot pass a negative expectation. Preserve observed RADIUS response, peer completion, keying status, and certificate-validation evidence as separate facts.

## Security design

Encrypt reusable credential values and private keys with a per-installation master key. Keep that key in a dedicated `/data/secrets/` directory (0700, key file 0600), not source, ordinary logs, arguments, or exported database snapshots. Make all stored application data private. Document that a backup containing both the key and database does not protect against complete backup theft; host administrators remain trusted. An external mounted master key can be supported without a competing fallback after an explicit configured key fails. Never silently replace a missing key for an existing encrypted database.

Store only sanitized logs and history snapshots. Do not enable eapol_test key-material debugging. Redact supplied secrets and encoded forms; suppress sensitive key/challenge-response dumps and credential-bearing RADIUS attributes. Bound total logs, individual lines, uploads, and history retention. Avoid ordinary request body logging.

Use private per-run temporary directories and files. Pass the RADIUS secret through a protected file; never use upstream `-s VALUE` from the web app. Launch argument arrays without a shell, enforce an overall deadline including preparation, and terminate/reap the owned process group on cancellation or timeout. Remove owned run files after every outcome. Use supported wpa configuration encoding (hex strings if appropriate) for identity/password inputs rather than brittle string interpolation or restrictions that exclude ordinary strong-password characters. Never load arbitrary file paths, engines, or modules from UI data.

Tests must cover authentication/CSRF boundaries, secret redaction and encryption, certificate key matching and signing, command/config injection, cancellation/timeouts, interrupted-run recovery, and result assertions. Real integration tests use separate FreeRADIUS infrastructure and must distinguish a skipped/unavailable server from a successful authentication test.
