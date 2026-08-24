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

PACKAGE_CONTENTS="$(tar -tzf "$PACKAGE_PATH")"
TOP_LEVEL="$(printf '%s\n' "$PACKAGE_CONTENTS" | sed 's#^\./##' | cut -d/ -f1 | sort -u)"
if [[ "$TOP_LEVEL" != "$APP_ID" ]]; then
  echo "Invalid package top-level directory: $TOP_LEVEL" >&2
  exit 1
fi

if printf '%s\n' "$PACKAGE_CONTENTS" | grep -Eq '(^|/)(\.DS_Store|\._|__MACOSX)(/|$)'; then
  echo "Package contains macOS metadata files." >&2
  exit 1
fi

if ! printf '%s\n' "$PACKAGE_CONTENTS" | grep -q "^$APP_ID/appserver/static/appLogo.png$"; then
  echo "Package is missing appserver/static/appLogo.png." >&2
  exit 1
fi

if printf '%s\n' "$PACKAGE_CONTENTS" | grep -Eq '(^|/)(__pycache__|.*\.pyc)$'; then
  echo "Package contains generated Python cache files." >&2
  exit 1
fi

LEGACY_ASSETS='dei_design_system_v1\.css|persistent_environment\.js|mitre_workspace\.js|dei_home_globe_v[56]\.css|command_center\.css|dei_workspace_layout_v12\.js'
if printf '%s\n' "$PACKAGE_CONTENTS" | grep -Eq "(^|/)($LEGACY_ASSETS)$"; then
  echo "Package contains retired static assets." >&2
  exit 1
fi

printf 'Created %s\n' "$PACKAGE_PATH"
printf 'Validated gzip integrity and top-level app directory.\n'
printf 'Install through Apps > Manage Apps > Install app from file.\n'
