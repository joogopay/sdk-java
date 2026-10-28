#!/usr/bin/env bash
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
: "${BC_JAR:?Set BC_JAR to an approved bcprov jar (example tested with bcprov-jdk18on 1.86)}"
test -f "$BC_JAR" || { echo "BC_JAR is not a file" >&2; exit 1; }
CLASSES=$(mktemp -d "${TMPDIR:-/tmp}/joogopay-java8.XXXXXX")
trap 'rm -rf "$CLASSES"' EXIT
JAVAC=${JAVAC:-javac}
JAVA=${JAVA:-java}
if "$JAVAC" -version 2>&1 | grep -q 'javac 1.8'; then
    options=(-source 8 -target 8)
else
    options=(--release 8)
fi
"$JAVAC" "${options[@]}" -encoding UTF-8 -cp "$BC_JAR" -d "$CLASSES" \
    "$HERE/ProtocolAdapter.java" "$HERE/ProtocolAdapterCheck.java" "$@"
"$JAVA" -cp "$CLASSES:$BC_JAR" ProtocolAdapterCheck
