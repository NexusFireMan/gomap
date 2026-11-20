#!/usr/bin/env bash
set -euo pipefail

root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
export ANDROID_HOME="${ANDROID_HOME:-$HOME/Android/Sdk}"
export ANDROID_NDK_HOME="${ANDROID_NDK_HOME:-$ANDROID_HOME/ndk/30.0.16248370}"
export JAVA_HOME="${JAVA_HOME:-/usr/lib/jvm/java-21-openjdk-amd64}"

if [[ ! -x "$JAVA_HOME/bin/javac" || ! -f "$ANDROID_NDK_HOME/source.properties" ]]; then
  echo "Configure JAVA_HOME (JDK 21), ANDROID_HOME and ANDROID_NDK_HOME before building." >&2
  exit 1
fi

mkdir -p "$root/android/build/tools"
export PATH="$root/android/build/tools:$JAVA_HOME/bin:$PATH"
cd "$root/android/bindings"
go mod verify
go build -o "$root/android/build/tools/gobind" golang.org/x/mobile/cmd/gobind
go tool gomobile bind -trimpath -target=android/arm64,android/amd64 -androidapi=31 \
  -javapkg=com.nexusfireman.gomap -o "$root/android/build/gomap.aar" \
  github.com/NexusFireMan/gomap/v2/mobile
go run ./cmd/checkaar "$root/android/build/gomap.aar"
