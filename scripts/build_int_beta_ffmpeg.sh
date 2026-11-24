#!/usr/bin/env bash
set -euo pipefail

# The release signature was verified against this primary key. Require the
# same signer and the exact bytes again before extracting the archive.
fingerprint=FCF986EA15E6E293A5644F10B4322F04D67658D8
release_sha=1a4d394ae63d190a526cd052eb4415c156b5c5e2df37efab41a7de0b8fde2433
printf '%s  %s\n' "$release_sha" ffmpeg-9.1.tar.xz | sha256sum --check
export GNUPGHOME
GNUPGHOME="$(mktemp -d)"
gpg --batch --import ffmpeg-release-key.asc
gpg --batch --status-fd 1 --verify ffmpeg-9.1.tar.xz.asc ffmpeg-9.1.tar.xz > signature.txt
awk -v fingerprint="$fingerprint" '$2 == "VALIDSIG" && $3 == fingerprint && $NF == fingerprint {found = 1} END {exit !found}' signature.txt
tar -xf ffmpeg-9.1.tar.xz
cd ffmpeg-9.1
output="${DESTDIR:-}/opt/clipforge/media"
./configure --prefix=/opt/clipforge/media \
  --disable-doc --disable-debug --disable-autodetect --disable-everything --disable-x86asm \
  --disable-network --disable-ffplay --enable-ffmpeg --enable-ffprobe --enable-gpl --enable-libx264 \
  --enable-protocol=file,pipe --enable-demuxer=mov --enable-muxer=mp4,pcm_s16le \
  --enable-decoder=h264,aac --enable-encoder=libx264,aac,pcm_s16le --enable-parser=h264,aac \
  --enable-filter=scale,setsar,setpts,pad,asetpts,aresample,aformat,format,fps,transpose,hflip,vflip,rotate
make -j "$(nproc)"
mkdir -p "$output/bin" "$output/provenance"
install -m 0555 ffmpeg ffprobe "$output/bin/"
install -m 0444 COPYING.GPLv2 ../signature.txt "$output/provenance/"
printf '%s\n' "$release_sha" > "$output/provenance/source-sha256"
for tool in ffmpeg ffprobe; do
    binary="$output/bin/$tool"
    sha256sum "$binary" | cut -d' ' -f1 > "$binary.sha256"
    "$binary" -version > "$output/provenance/$tool-version"
    ldd "$binary" > "$output/provenance/$tool-library-list"
    if grep -Eq 'libxml|not found' "$output/provenance/$tool-library-list"; then
        exit 1
    fi
done
