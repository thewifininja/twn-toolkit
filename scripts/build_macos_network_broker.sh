#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
SOURCE="$ROOT/native/macos_network_broker.c"
OUTPUT="$ROOT/twn_toolkit/bin/twn-network-broker"

mkdir -p "$(dirname -- "$OUTPUT")"
xcrun clang \
  -arch arm64 \
  -arch x86_64 \
  -mmacosx-version-min=12.0 \
  -Os \
  -Wall \
  -Wextra \
  -Werror \
  "$SOURCE" \
  -o "$OUTPUT"
codesign --force --sign - --timestamp=none "$OUTPUT"
chmod 755 "$OUTPUT"

file "$OUTPUT"
codesign --verify --verbose=2 "$OUTPUT"
