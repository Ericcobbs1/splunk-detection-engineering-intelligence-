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
  --exclude '__pycache__' \
  --exclude '*.pyc' \
  "$APP_DIR/" "$STAGING_DIR/$APP_ID/"

(
  cd "$STAGING_DIR"
  tar -czf "$PACKAGE_PATH" "$APP_ID"
)

printf 'Created %s\n' "$PACKAGE_PATH"
printf 'Install through Apps > Manage Apps > Install app from file.\n'
