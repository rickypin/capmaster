#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

if [[ -z "${VIRTUAL_ENV:-}" ]]; then
  echo "error: please activate the project virtual environment before building" >&2
  exit 1
fi

if ! command -v pyinstaller >/dev/null 2>&1; then
  echo "error: pyinstaller is not installed in the current environment" >&2
  exit 1
fi

if ! command -v tshark >/dev/null 2>&1; then
  echo "error: tshark is required at runtime; install it via Homebrew (brew install wireshark)" >&2
  exit 1
fi

VERSION="$(python -m capmaster --version 2>/dev/null | awk '{print $NF}')"
if [[ -z "${VERSION}" ]]; then
  VERSION="$(python - <<'PY'
from pathlib import Path
import tomllib
pyproject = Path(__file__).resolve().parents[1] / "pyproject.toml"
data = tomllib.loads(pyproject.read_text())
print(data["project"]["version"])
PY
  )"
fi
if [[ -z "${VERSION}" ]]; then
  echo "error: unable to determine capmaster version" >&2
  exit 1
fi

rm -rf build dist
rm -rf artifacts/capmaster-macos-*

pyinstaller --clean --noconfirm packaging/capmaster-mac.spec

if [[ ! -f dist/capmaster ]]; then
  BUILD_EXE="build/capmaster-mac/capmaster"
  if [[ -f "${BUILD_EXE}" ]]; then
    mkdir -p dist
    cp "${BUILD_EXE}" dist/capmaster
  else
    echo "error: expected PyInstaller to produce dist/capmaster" >&2
    exit 1
  fi
fi

codesign --force --timestamp --sign - dist/capmaster

mkdir -p artifacts
OUT="artifacts/capmaster-macos-$(uname -m)-v${VERSION}"
rm -f "${OUT}" "${OUT}.tar.gz"
cp dist/capmaster "${OUT}"

tar -C artifacts -czf "${OUT}.tar.gz" "$(basename "${OUT}")"
shasum -a 256 "${OUT}.tar.gz"

echo "Built ${OUT}.tar.gz"
