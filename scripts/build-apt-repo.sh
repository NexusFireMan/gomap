#!/usr/bin/env bash

set -euo pipefail

if [[ $# -lt 3 ]]; then
  echo "usage: $0 <deb-dir> <output-dir> <public-base-url> [distribution] [component]" >&2
  exit 1
fi

DEB_DIR="$1"
OUT_DIR="$2"
BASE_URL="${3%/}"
DISTRIBUTION="${4:-stable}"
COMPONENT="${5:-main}"
PROJECT="gomap"
POOL_DIR="${OUT_DIR}/pool/${COMPONENT}/g/${PROJECT}"
DIST_DIR="${OUT_DIR}/dists/${DISTRIBUTION}/${COMPONENT}"

if [[ ! -d "${DEB_DIR}" ]]; then
  echo "deb dir not found: ${DEB_DIR}" >&2
  exit 1
fi

mapfile -t DEBS < <(find "${DEB_DIR}" -maxdepth 1 -type f -name '*.deb' | sort)
if [[ ${#DEBS[@]} -eq 0 ]]; then
  echo "no .deb packages found in ${DEB_DIR}" >&2
  exit 1
fi

rm -rf "${OUT_DIR}"
mkdir -p "${POOL_DIR}" "${DIST_DIR}/binary-amd64" "${DIST_DIR}/binary-arm64"

for deb in "${DEBS[@]}"; do
  cp "${deb}" "${POOL_DIR}/"
done

dpkg-scanpackages -a amd64 --multiversion "${OUT_DIR}/pool" /dev/null > "${DIST_DIR}/binary-amd64/Packages"
gzip -9fk "${DIST_DIR}/binary-amd64/Packages"

dpkg-scanpackages -a arm64 --multiversion "${OUT_DIR}/pool" /dev/null > "${DIST_DIR}/binary-arm64/Packages"
gzip -9fk "${DIST_DIR}/binary-arm64/Packages"

cat > "${OUT_DIR}/apt-ftparchive.conf" <<EOF
APT::FTPArchive::Release {
  Origin "NexusFireMan";
  Label "gomap";
  Suite "${DISTRIBUTION}";
  Codename "${DISTRIBUTION}";
  Architectures "amd64 arm64";
  Components "${COMPONENT}";
  Description "GoMap APT repository";
};
EOF

apt-ftparchive -c "${OUT_DIR}/apt-ftparchive.conf" release "${OUT_DIR}/dists/${DISTRIBUTION}" > "${OUT_DIR}/dists/${DISTRIBUTION}/Release"

KEY_URL="${BASE_URL}/gomap-archive-keyring.gpg"
REPO_ENTRY="deb [signed-by=/usr/share/keyrings/gomap-archive-keyring.gpg] ${BASE_URL} ${DISTRIBUTION} ${COMPONENT}"

cat > "${OUT_DIR}/index.html" <<EOF
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>gomap APT Repository</title>
    <style>
      :root {
        color-scheme: light;
        --bg: #0f172a;
        --panel: #111827;
        --ink: #e5e7eb;
        --muted: #94a3b8;
        --accent: #38bdf8;
      }
      body {
        margin: 0;
        font-family: "JetBrains Mono", "Fira Code", monospace;
        background: radial-gradient(circle at top, #1e293b 0%, var(--bg) 50%);
        color: var(--ink);
      }
      main {
        max-width: 880px;
        margin: 0 auto;
        padding: 56px 24px 80px;
      }
      .panel {
        background: rgba(17, 24, 39, 0.9);
        border: 1px solid rgba(56, 189, 248, 0.2);
        border-radius: 18px;
        padding: 24px;
        box-shadow: 0 20px 80px rgba(15, 23, 42, 0.35);
      }
      h1 {
        margin-top: 0;
        font-size: 2.2rem;
      }
      p, li {
        color: var(--muted);
        line-height: 1.6;
      }
      code, pre {
        font-family: inherit;
      }
      pre {
        overflow-x: auto;
        padding: 16px;
        background: rgba(2, 6, 23, 0.9);
        border-radius: 14px;
        border: 1px solid rgba(148, 163, 184, 0.2);
      }
      a {
        color: var(--accent);
      }
      .muted {
        font-size: 0.95rem;
      }
    </style>
  </head>
  <body>
    <main>
      <section class="panel">
        <h1>gomap APT repository</h1>
        <p>APT repository for Kali, Parrot, Debian, and compatible derivatives.</p>
        <pre><code>curl -fsSL ${KEY_URL} | sudo gpg --dearmor -o /usr/share/keyrings/gomap-archive-keyring.gpg
echo '${REPO_ENTRY}' | sudo tee /etc/apt/sources.list.d/gomap.list > /dev/null
sudo apt update
sudo apt install gomap</code></pre>
        <p class="muted">This repository is published automatically from tagged GitHub releases.</p>
      </section>
    </main>
  </body>
</html>
EOF

echo "${REPO_ENTRY}" > "${OUT_DIR}/gomap.list"
