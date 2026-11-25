#!/usr/bin/env bash
set -euo pipefail

# Require the exact release bytes and approved signing fingerprints before extracting.
release_sha=1a4d394ae63d190a526cd052eb4415c156b5c5e2df37efab41a7de0b8fde2433
libass_sha=2dca25c0e0c837ddf00b52011b3f82cac1e4ddd3ad018227806b0c2288864acc
libass_fix_sha=0636cdd5088b033063a1459d07dbf66b4a5e94083d0b478e37a14440820b331c
export GNUPGHOME
GNUPGHOME="$(mktemp -d)"

verify_release() {
    local archive="$1" key="$2" digest="$3" signer="$4" primary="$5" record="$6"
    printf '%s  %s\n' "$digest" "$archive" | sha256sum --check
    gpg --batch --import "$key"
    gpg --batch --status-fd 1 --verify "$archive.asc" "$archive" > "$record"
    awk -v signer="$signer" -v primary="$primary" \
        '$2 == "VALIDSIG" && $3 == signer && $NF == primary {found = 1} END {exit !found}' "$record"
}

verify_release ffmpeg-9.1.tar.xz ffmpeg-release-key.asc "$release_sha" \
    FCF986EA15E6E293A5644F10B4322F04D67658D8 FCF986EA15E6E293A5644F10B4322F04D67658D8 signature.txt
verify_release libass-0.17.5.tar.xz libass-release-key.asc "$libass_sha" \
    DDAFC19E46B2AD2D6B26F84397A08E0CFFD70951 5EE63F2A71BF132CFE3567E1DFFE615F2824C720 libass-signature.txt
printf '%s  %s\n' "$libass_fix_sha" libass-d570c2f.patch | sha256sum --check

# The signed upstream release fixes CVE-2026-61627. Apply the reviewed
# CVE-2026-95127 patch before linking the static archive.
libass_prefix="$PWD/libass-install"
tar -xf libass-0.17.5.tar.xz
(
    cd libass-0.17.5
    patch --batch --forward --fuzz=0 -p1 < ../libass-d570c2f.patch
    ./configure --prefix="$libass_prefix" --disable-asm --disable-shared --enable-static
    make -j "$(nproc)"
    make install
)
export PKG_CONFIG_PATH="$libass_prefix/lib/pkgconfig"
test "$(pkg-config --modversion libass)" = 0.17.5
tar -xf ffmpeg-9.1.tar.xz
cd ffmpeg-9.1
output="${DESTDIR:-}/opt/clipforge/media"
./configure --prefix=/opt/clipforge/media \
  --pkg-config-flags=--static \
  --disable-doc --disable-debug --disable-autodetect --disable-everything --disable-x86asm \
  --disable-network --disable-ffplay --enable-ffmpeg --enable-ffprobe --enable-gpl --enable-libx264 --enable-libass \
  --enable-protocol=file,pipe --enable-demuxer=mov --enable-muxer=mp4,pcm_s16le \
  --enable-decoder=h264,aac --enable-encoder=libx264,aac,pcm_s16le --enable-parser=h264,aac \
  --enable-filter=scale,setsar,setpts,pad,asetpts,aresample,aformat,format,fps,transpose,hflip,vflip,rotate,ass
make -j "$(nproc)"
mkdir -p "$output/bin" "$output/provenance"
install -m 0555 ffmpeg ffprobe "$output/bin/"
install -m 0444 COPYING.GPLv2 ../signature.txt ../libass-signature.txt "$output/provenance/"
install -m 0444 ../libass-0.17.5/COPYING "$output/provenance/libass-COPYING"
printf '%s\n' "$release_sha" > "$output/provenance/source-sha256"
printf '%s\n' "$libass_sha" > "$output/provenance/libass-source-sha256"
printf '%s\n' 0.17.5 > "$output/provenance/libass-version"
printf '%s  %s\n' "$libass_fix_sha" d570c2f5ed55844ec9b77b085deb3cb8ef59cb4a \
    > "$output/provenance/libass-backport"
for tool in ffmpeg ffprobe; do
    binary="$output/bin/$tool"
    sha256sum "$binary" | cut -d' ' -f1 > "$binary.sha256"
    "$binary" -version > "$output/provenance/$tool-version"
    ldd "$binary" > "$output/provenance/$tool-library-list"
    if grep -Eq 'libxml|libass\.so|not found' "$output/provenance/$tool-library-list"; then
        exit 1
    fi
done
