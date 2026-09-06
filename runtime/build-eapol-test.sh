#!/bin/sh
# Build only the pinned eapol_test client; do not build an authentication server.
set -eu
if [ "$#" -ne 2 ]; then
    echo "usage: build-eapol-test.sh BUILD_DIRECTORY OUTPUT_BINARY" >&2
    exit 2
fi
runtime_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$runtime_dir/source.env"
build_dir=$1
output=$2
mkdir -p "$build_dir"
build_dir=$(CDPATH= cd -- "$build_dir" && pwd)
archive="$build_dir/wpa_supplicant-$WPA_VERSION.tar.gz"
curl --fail --show-error --silent --location --proto '=https' --tlsv1.2 \
    --connect-timeout 15 --max-time 180 "$WPA_URL" --output "$archive"
printf '%s  %s\n' "$WPA_SHA256" "$archive" | sha256sum --check --strict -
tar --extract --gzip --file "$archive" --directory "$build_dir"
source_dir="$build_dir/wpa_supplicant-$WPA_VERSION"
grep -F "#define VERSION_STR \"$WPA_VERSION\"" "$source_dir/src/common/version.h"
for patch_file in "$runtime_dir"/patches/*.patch; do
    patch --directory "$source_dir" --strip 1 --batch --forward --fuzz 0 < "$patch_file"
done
cp "$runtime_dir/eapol_test.config" "$source_dir/wpa_supplicant/.config"
make --directory "$source_dir/wpa_supplicant" -j2 eapol_test
install -D -m 0755 "$source_dir/wpa_supplicant/eapol_test" "$output"
"$output" -v
