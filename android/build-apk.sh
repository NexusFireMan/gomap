#!/usr/bin/env bash
set -euo pipefail

root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
export ANDROID_HOME="${ANDROID_HOME:-$HOME/Android/Sdk}"
export JAVA_HOME="${JAVA_HOME:-/usr/lib/jvm/java-21-openjdk-amd64}"
export PATH="$JAVA_HOME/bin:$PATH"

if [[ ! -f "$ANDROID_HOME/platforms/android-37.0/android.jar" ]]; then
  echo 'Install platforms;android-37.0 and Build Tools 36.0.0 after reviewing their licenses.' >&2
  exit 1
fi
bash "$root/android/build-aar.sh"
"$root/android/gradlew" -p "$root/android" :app:testDebugUnitTest :app:lintDebug \
  :app:assembleDebug :app:assembleDebugAndroidTest --no-daemon

apk="$root/android/app/build/outputs/apk/debug/app-debug.apk"
tools="$ANDROID_HOME/build-tools/36.0.0"
analyzer="${ANDROID_CMDLINE_TOOLS:-$ANDROID_HOME/cmdline-tools/latest}/bin/apkanalyzer"
"$tools/apksigner" verify "$apk"
"$tools/zipalign" -c -P 16 4 "$apk"
[[ "$("$analyzer" manifest min-sdk "$apk")" == "31" ]]
[[ "$("$analyzer" manifest target-sdk "$apk")" == "37" ]]
(cd "$root/android/bindings" && go run ./cmd/checkaar --native-apk "$apk")
echo "Debug APK ready: $apk"
echo 'Native device/instrumentation execution remains a separate validation step.'
