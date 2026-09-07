# EAPOL Test Kit

A personal RADIUS/EAP workbench that runs eapol_test behind a web interface. It is intended for Docker on Debian. FreeRADIUS is a separate target, not part of the image.

Version 0.1.0. Behavior is defined here and in `docs/implementation-contract.md`. Tested environment and image correspondence are in `runtime/VERIFICATION.md`.

## Start the kit

Install Docker Engine and the Docker Compose plugin. The workbench password is separate from RADIUS credentials. Default publication is `127.0.0.1:8080`.

### Localhost

```sh
docker compose up --build -d
```

Open `http://127.0.0.1:8080` and create the workbench password on the setup screen.

To keep localhost publication on a remote host, forward the port:

```sh
ssh -L 8080:127.0.0.1:8080 YOUR_SSH_USER@YOUR_DEBIAN_HOST
```

Open `http://127.0.0.1:8080` locally and keep the SSH session open.

### Host address

`EAPOLKIT_BIND_ADDRESS` publishes the web UI on that IPv4 address and adds it to the default HTTP hosts: `localhost`, `127.0.0.1`, `::1`, and the bind IP. The listener is HTTP.

In this directory, create `.env`:

```dotenv
EAPOLKIT_BIND_ADDRESS=YOUR_HOST_IPV4
```

On a new volume, set the password from the Debian terminal, then start the service:

```sh
docker compose build &&
docker compose run --rm --no-deps kit python -m eapolkit.setup &&
docker compose up -d
```

Enter the workbench password twice. Input is not echoed. The terminal reader accepts 1–4096 UTF-8 characters. Overlength or invalid input is rejected without using a prefix. Erase, kill, word erase, EOF, signals, flow control, and literal-next follow the terminal's configured controls. Setup writes the password hash to the data volume and does not publish ports. An existing password is left unchanged.

If the volume already has a password, run `docker compose up --build -d`.

Open `http://YOUR_HOST_IPV4:8080` and sign in. Set `EAPOLKIT_PORT` in `.env` to publish a different port.

### HTTPS reverse proxy

Initialize the password with the terminal setup command, then put the kit behind your reverse proxy. Set `EAPOLKIT_SECURE_COOKIES=1`. Set `EAPOLKIT_ALLOWED_HOSTS` to the host names you use, including `127.0.0.1` for the container health check. A nonempty `EAPOLKIT_ALLOWED_HOSTS` replaces the defaults.

Without an override, accepted hosts are `localhost`, `127.0.0.1`, `::1`, and the concrete IP from `EAPOLKIT_BIND_ADDRESS`. Wildcard binds such as `0.0.0.0` and `::` do not add extra HTTP hosts. Host, origin, and CSRF checks stay on.

## Run an authentication test

1. Add a RADIUS target with its address, UDP port, and shared secret.
2. Import the CA chain that authenticates the RADIUS server.
3. Create a profile from an EAP-TLS, PEAP-MSCHAPv2, TTLS-PAP, or TTLS-MSCHAPv2 preset.
4. Set the identity, expected server certificate name, and applicable credentials or client certificate.
5. Inspect the generated configuration preview.
6. Select the target and profile, and then start the run.

Saved targets and profiles are independent. A target is the RADIUS server (host, port, secret, NAS-Identifier, NAS-IP-Address, timeout). A profile is the EAP method, identity, certificates, Calling-Station-Id, and extra RADIUS attributes. Omitting a password on a profile update keeps the saved value. Duplicating a profile copies the saved password on the server.

Custom RADIUS attributes support text, unsigned integers, hexadecimal bytes, and IPv4 addresses. Hexadecimal input is the attribute payload, not the outer type/length header. Generated and custom attributes are passed to the client through a protected file. Private values stay hidden after saving; making a private value public requires a replacement value and confirmation. Known credential-bearing attributes stay private.

The generated configuration uses managed certificate assets.

## RADIUS packet source

FreeRADIUS authenticates the UDP source address and shared secret of incoming packets. With ordinary Docker bridge networking, that source is usually the Debian host's outbound address.

`NAS-IP-Address` is a RADIUS attribute. Changing it does not select the UDP source. Register the observed packet source on the server.

One authentication run is active at a time. Runs have an overall timeout and can be cancelled. A container restart marks an unfinished run as interrupted.

## Certificates

Keep server trust and client identity separate:

- **Server trust:** Import a PEM CA certificate or chain that validates the RADIUS server. Set the expected server name on the profile.
- **Client identity:** Import a certificate with its matching private key, or a protected PKCS#12/PFX bundle.
- **Existing PKI:** Generate a key and CSR, complete that saved request with the signed certificate.
- **Lab issuer:** Generate a lab CA and issue a client certificate, then configure FreeRADIUS to trust that issuer.

Public certificate and CSR downloads omit the private key. Exporting a private identity is an explicit PFX operation with a passphrase. Import passphrases are used only to unlock the uploaded material.

## Results

A run records the observed result: accept, reject, certificate error, timeout, cancellation, or interruption. Accept requires completed EAP processing. Returned authorization attributes, if shown, are the values the server sent.

## Data

The named Docker volume holds application metadata, certificate assets, and encrypted credentials. The process runs as UID/GID 10001 with a read-only image filesystem and a private writable data area.

Reusable secrets and private keys are encrypted with a per-installation master key in the volume's secrets directory. Each run gets a private temporary directory. The client reads the RADIUS secret from a protected file. Stored logs, previews, and run reports omit secret values.

`docker compose down -v` deletes the named volume.

## License

The original kit code and documentation are licensed under the [MIT license](LICENSE).
Upstream wpa_supplicant material and the native patches retain their BSD-3-Clause
terms. See [Third-party notices](THIRD_PARTY_NOTICES.md) for the scope, retained
upstream notices, and dependency licensing limits.
