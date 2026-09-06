# EAPOL Test Kit

A personal RADIUS/EAP workbench that runs eapol_test behind a web interface. The kit is intended for Docker on Debian. FreeRADIUS is a target and separate integration-test service, not a bundled component.

## Status

Version 0.1.0 has passed end-to-end authentication tests against an external FreeRADIUS server, including all four methods through the Docker web UI. The validation section describes the tested environment and limits. The implementation contract is in `docs/implementation-contract.md`.

## Start the kit

Install Docker Engine and the Docker Compose plugin on your Debian host. The default publication is localhost only. The workbench password is separate from RADIUS credentials. Do not publish this credential-handling tool directly to the internet.

### Trusted-LAN HTTP access from a CLI-only Debian host

This is an opt-in plaintext deployment, not an HTTPS connection. HTTP does not encrypt the workbench password, session cookies, RADIUS credentials, or uploaded and downloaded private material in transit. Other systems on the network path can read or modify that traffic. Storage encryption does not protect network traffic. Use this option only on a trusted LAN. Use an SSH tunnel or HTTPS if you need transport encryption.

Initial deployment needs only a terminal on the Debian host. You use a browser on another LAN computer afterward; no Debian desktop, Debian browser, or persistent SSH tunnel is required.

1. In this directory, create or edit the `.env` file. Set the Debian host's LAN IPv4 address, replacing `YOUR_DEBIAN_LAN_IPV4` with that address:

   ```dotenv
   EAPOLKIT_BIND_ADDRESS=YOUR_DEBIAN_LAN_IPV4
   ```

   This one setting selects the published interface and adds that IP to the default accepted HTTP hosts. You do not need a second host setting. Keep `EAPOLKIT_SECURE_COOKIES` unset for HTTP. If you previously set `EAPOLKIT_ALLOWED_HOSTS`, remove that override to use the automatic defaults, or include the LAN IP in your explicit list.

2. For a new installation, run this sequence in the Debian terminal:

   ```sh
   docker compose build &&
   docker compose run --rm --no-deps kit python -m eapolkit.setup &&
   docker compose up -d
   ```

   Enter a unique workbench password twice when prompted. Input is not echoed. The terminal accepts 1–4096 UTF-8 characters without truncating long lines. An overlength or invalid entry is rejected without using a prefix. Erase, line and word erase, EOF, signals, flow control, and literal-next quoting use the terminal’s configured controls. The setup command writes the password hash to the same private data volume that the web service uses. It does not start the web service or publish its ports. Do not add `--service-ports` or `--publish` to this command. The `&&` sequence starts the service only after setup succeeds.

   If setup fails or is cancelled, do not start LAN publication until setup succeeds. Rerunning setup never replaces an existing password. If the workbench already has a password, skip initialization and run `docker compose up --build -d` instead; saved data and the password remain in the existing volume.

3. On another LAN computer, open `http://YOUR_DEBIAN_LAN_IPV4:8080`, replacing the placeholder with the same Debian address. Sign in with the workbench password.

The default port is 8080. Set `EAPOLKIT_PORT` in `.env` if you need another published port, and use that port in the browser URL. The kit does not configure host addresses, routing, or firewalls. The host must already be reachable from the client.

### Localhost access

From this directory, run:

```sh
docker compose up --build -d
```

Open `http://127.0.0.1:8080` on the same computer. Create the workbench password on the setup screen. This first-run web setup remains available if you do not use terminal setup.

For a remote Debian host, you can keep localhost publication and use an SSH tunnel:

```sh
ssh -L 8080:127.0.0.1:8080 YOUR_SSH_USER@YOUR_DEBIAN_HOST
```

Then open `http://127.0.0.1:8080` on your computer. Keep the SSH session open during use.

### HTTPS reverse proxy

For encrypted network access without a persistent SSH tunnel, put the kit behind your HTTPS reverse proxy. Initialize the password with the terminal setup command before publishing proxy access. Set `EAPOLKIT_SECURE_COOKIES=1`. Set `EAPOLKIT_ALLOWED_HOSTS` to the host names that you use, retaining `127.0.0.1` for the container health check and `localhost` for local access. For example, use `localhost,127.0.0.1,YOUR_HOST_NAME`.

A nonempty `EAPOLKIT_ALLOWED_HOSTS` is an explicit override, not an addition to the defaults. Without an override, the accepted hosts are `localhost`, `127.0.0.1`, `::1`, and the concrete IP from `EAPOLKIT_BIND_ADDRESS`. Wildcard bind addresses such as `0.0.0.0` and `::` do not permit arbitrary HTTP hosts. Host, origin, and CSRF checks remain enabled for every deployment option.

## Run an authentication test

1. Add a RADIUS target with its address, UDP port, and shared secret.
2. Import the CA chain that authenticates the RADIUS server.
3. Create a profile from an EAP-TLS, PEAP-MSCHAPv2, TTLS-PAP, or TTLS-MSCHAPv2 preset.
4. Set the identity, expected server certificate name, and applicable credentials or client certificate.
5. Inspect the generated configuration preview.
6. Select the target and profile, and then start the run.

Saved targets and profiles are independent. Use the same profile with several targets, or several profiles with one target. Advanced fields expose anonymous identity, TLS versions, fragment size, NAS attributes, and expected outcomes. An omitted password on a profile update preserves the saved value. A server-side profile copy preserves its saved password without returning it to the browser.

Custom RADIUS attributes support text, unsigned integers, hexadecimal bytes, and IPv4 addresses. Hexadecimal input supplies the attribute payload, not its outer type/length header. Vendor-specific and extended payloads are supported without guessing their internal format.

Private attribute values are hidden after saving. An unchanged row preserves its saved value; making a private value public requires a replacement value and explicit confirmation. Known credential-bearing attributes stay private. The client reads generated and custom attributes from a protected file rather than command-line values.

The generated configuration uses managed certificate assets. The kit does not execute arbitrary shell commands, uploaded wpa configuration directives, plugins, or user-selected filesystem paths.

## Configure the FreeRADIUS client relationship

FreeRADIUS must recognize the address from which RADIUS packets arrive and use the matching shared secret. With ordinary Docker bridge networking to an external server, that source is usually the Debian host's outbound address. It is not necessarily the container address.

`NAS-IP-Address` is a RADIUS attribute. Changing it does not bind the UDP source address or change Docker NAT behavior. Register the observed packet source on the server. The kit does not modify FreeRADIUS client registrations or certificate trust.

Only one authentication run is active at a time. Runs have an overall timeout and can be cancelled. A container restart marks an unfinished run as interrupted; it does not retry credentials automatically.

## Manage certificates

Keep server trust and client identity separate:

- **Server trust:** Import a PEM CA certificate or chain that validates the RADIUS server. Configure the expected server name in the profile.
- **Client identity:** Import a certificate with its matching private key, or a protected PKCS#12/PFX bundle.
- **Existing PKI:** Generate a key and certificate signing request (CSR), have your PKI sign the CSR, and then complete that saved request with the returned certificate.
- **Lab issuer:** Generate a lab CA, and then issue a client certificate. Configure the external FreeRADIUS server to trust that client issuer and apply its identity policy.

Generating a certificate does not enroll it on the RADIUS server. A CA used to validate the server does not have to be the CA that issued the client certificate.

Public certificate and CSR downloads contain no private key. A private-identity export is a separate explicit operation and requires a PFX passphrase. Import passphrases are used only to unlock the uploaded material.

## Interpret results

A run reports its observed outcome separately from whether it met the selected expectation:

- An expected successful authentication needs successful EAP processing, not just a matching text fragment.
- An expected rejection needs evidence of a rejection.
- An expected server certificate error needs certificate-validation evidence.
- A timeout, launch error, cancellation, or interrupted process never passes a rejection test.

Use **Duplicate as a negative test** to start from a working profile and change one condition. Server-side policy failures are not always distinguishable from the client. Check the FreeRADIUS logs when the client has insufficient evidence.

On narrow screens, scroll the history table horizontally to view all result columns and actions.

This tool exercises RADIUS/EAP directly. It does not test Wi-Fi association, a switch port, or actual VLAN enforcement. Returned authorization attributes, if shown, establish only what the server returned.

## Data and security

The named Docker volume contains application metadata, certificate assets, and protected credentials. The application runs as UID/GID 10001, with a read-only image filesystem and a private writable data area. It needs no host network, elevated Linux capabilities, or Docker socket.

Reusable secret values and private keys are encrypted. A per-installation master key is stored in the dedicated private secrets directory. Protect the whole volume and any backup. A backup containing both the encrypted database and its master key does not protect against complete backup theft. Host administrators remain trusted. Do not delete or regenerate the master key for existing data.

Each run receives a private temporary directory. The patched eapol_test reads the RADIUS secret from a protected file, not a command-line value. The application does not enable key-material debugging. Stored logs, previews, and exported run reports exclude secret values. Do not place actual credentials, private keys, application data, or backups in this source directory.

Run reports are diagnostic exports, not backups. Preserve the complete application volume for recovery. For a consistent offline backup, stop the kit when no run is active, copy the complete volume to protected storage outside the source tree, and then start the kit. Preserve ownership and restrictive permissions when restoring. Do not use `docker compose down -v` unless you intend to delete all saved workbench data.

## Validation

### CLI-only deployment update

The terminal reader and affected setup, API, and storage behavior passed 47 focused tests on 2026-09-06, including 24 real-PTY cases covering complete 4096-character UTF-8 input, delayed-suffix rejection without echo, and terminal restoration. The earlier CLI/backend checkpoint passed 243 tests; 11 optional UI tests were skipped. See `runtime/VERIFICATION.md` for the Docker Compose checkpoint and deployment limits. The native client is unchanged; the RADIUS and full browser matrices were not repeated for this deployment update.

### Original authentication validation

Tested on 2026-09-06 with Docker on Debian 13, Linux amd64, and an external FreeRADIUS 3.2.10 fixture using TLS 1.2. These results do not establish TLS 1.3 interoperability or physical switch-port behavior.

| Check | Verified scope |
| --- | --- |
| Backend | 213 API, storage, certificate, migration, and synthetic subprocess tests passed. Independent review rechecked result evidence, certificate-chain ordering, and secret redaction. |
| Web UI | Authentication, profiles, certificates, and protected attribute workflows passed local Chromium tests. On the final Docker image, all four methods passed through Chromium with successful EAP/keying evidence and checked report downloads. Desktop and 390 px history layouts passed geometry checks and visual review. |
| Native client | 21 real-binary checks passed as the non-root application user, including protected inputs, maximum credential lengths, typed certificate evidence, and forged-result controls. |
| Docker | The matching application image passed locked-dependency, installed-input, read-only filesystem, and HTTP startup checks. Shipped Compose data persistence passed on the earlier baseline. |
| External FreeRADIUS | 15 native cases and 18 HTTP API checks passed on the matching image: all four methods, password and certificate negatives, timeout classification, cancellation, and single-run enforcement. Private-attribute preservation and sanitized storage/exports also passed. FreeRADIUS remains outside the kit. |

The complete native and API matrices ran on the accepted application snapshot. The final image changes only the history-table stylesheet; every other installed input, the native binary, and all locked dependency versions match that snapshot. The final four-method browser run verified the updated image and its served stylesheet. The unchanged negative API matrix was not repeated for that visual correction. Exact image and test correspondence is recorded in `runtime/VERIFICATION.md`.

## License

The original kit code and documentation are licensed under the [MIT license](LICENSE).
Upstream wpa_supplicant material and the native patches retain their BSD-3-Clause
terms. See [Third-party notices](THIRD_PARTY_NOTICES.md) for the scope, retained
upstream notices, and dependency licensing limits.
