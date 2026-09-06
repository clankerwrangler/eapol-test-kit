# Third-party notices

## License scope

The original EAPOL Test Kit Python backend, static web UI, build and runtime
scripts, tests, documentation, and packaging configuration are licensed under
the [MIT license](LICENSE).

The following material is excluded from that MIT grant:

- The retained upstream notices in `runtime/licenses/wpa_supplicant-COPYING`
  and `runtime/licenses/wpa_supplicant-README` keep their existing terms.
- All four files in `runtime/patches/` contain or modify upstream
  wpa_supplicant material and remain under BSD-3-Clause, as documented in
  `runtime/SOURCE.md`.

The kit's MIT license does not relicense third-party material.

## wpa_supplicant and eapol_test

The build downloads the pinned wpa_supplicant 2.11 release and builds only its
`eapol_test` client. The source repository does not bundle the upstream source
archive or a prebuilt client binary. Version, download provenance, digest,
build configuration, and patch scope are documented in `runtime/SOURCE.md`
and `runtime/source.env`.

The upstream README credits Copyright (c) 2002-2024, Jouni Malinen and
contributors. It grants the three-clause BSD license, with the advertising
clause removed. The complete governing text is retained in the
[upstream README notice](runtime/licenses/wpa_supplicant-README).

For redistribution under those terms:

1. Retain the upstream copyright notice, all three conditions, and the
   disclaimer in source distributions.
2. Reproduce the same copyright notice, conditions, and disclaimer in the
   documentation or other materials accompanying binary distributions.
3. Do not use the copyright holders' or contributors' names to endorse or
   promote derived products without specific prior written permission.

Keep the complete upstream notices, not just this summary. The retained
[upstream COPYING notice](runtime/licenses/wpa_supplicant-COPYING) explains
that upstream discontinued its historical GPLv2 alternative on 2012-02-11.
This kit does not elect GPLv2 for the pinned release. Both upstream notice
files, including their original copyright years, are preserved unchanged.

The Dockerfile installs these upstream notices, the source manifest, the
build configuration, and the exact patches under
`/usr/local/share/doc/eapol_test/`. It installs this file and the kit's MIT
license under `/usr/local/share/doc/eapol-test-kit/`.

## Other dependencies

Python dependencies, Python and Debian base-image packages, OpenSSL, and
other build and runtime packages retain their own licenses and notices.
Declaring or installing a dependency does not place it under the kit's MIT
license. This document is not an exhaustive license inventory of a built
image. When redistributing an image, preserve the dependency notices and
satisfy the terms of the exact packages that it contains.
