#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP_DIR="$ROOT_DIR/app"
APP_ID="splunk_detection_engineering_intelligence"
VERSION="$(awk -F' = ' '/^version = / {print $2; exit}' "$APP_DIR/default/app.conf")"
DIST_DIR="$ROOT_DIR/dist"
PACKAGE_PATH="$DIST_DIR/${APP_ID}-${VERSION}.spl"
STAGING_DIR="$(mktemp -d)"

cleanup() {
  rm -rf "$STAGING_DIR"
}
trap cleanup EXIT

if [[ ! -d "$APP_DIR" ]]; then
  echo "App directory not found: $APP_DIR" >&2
  exit 1
fi

mkdir -p "$DIST_DIR"
rm -f "$PACKAGE_PATH"

mkdir -p "$STAGING_DIR/$APP_ID"
rsync -a \
  --exclude '.DS_Store' \
  --exclude '._*' \
  --exclude '__MACOSX' \
  --exclude '__pycache__' \
  --exclude '*.pyc' \
  "$APP_DIR/" "$STAGING_DIR/$APP_ID/"

(
  cd "$STAGING_DIR"
  COPYFILE_DISABLE=1 tar --format ustar -czf "$PACKAGE_PATH" "$APP_ID"
)

gzip -t "$PACKAGE_PATH"

TOP_LEVEL="$(tar -tzf "$PACKAGE_PATH" | sed 's#^\./##' | cut -d/ -f1 | sort -u)"
if [[ "$TOP_LEVEL" != "$APP_ID" ]]; then
  echo "Invalid package top-level directory: $TOP_LEVEL" >&2
  exit 1
fi

if tar -tzf "$PACKAGE_PATH" | grep -Eq '(^|/)(\.DS_Store|\._|__MACOSX)(/|$)'; then
  echo "Package contains macOS metadata files." >&2
  exit 1
fi

printf 'Created %s\n' "$PACKAGE_PATH"
printf 'Validated gzip integrity and top-level app directory.\n'
printf 'Install through Apps > Manage Apps > Install app from file.\n'
