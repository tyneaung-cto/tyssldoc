#!/usr/bin/env bash
set -euo pipefail

REPO="tyneaung-cto/tyssldoc"
BIN_NAME="tyssldoc"
INSTALL_DIR="/usr/local/bin"
API_URL="https://api.github.com/repos/${REPO}/releases/latest"

log() {
  printf '%s\n' "$*"
}

err() {
  printf 'Error: %s\n' "$*" >&2
  exit 1
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || err "required command not found: $1"
}

detect_os() {
  local os
  os="$(uname -s | tr '[:upper:]' '[:lower:]')"
  case "$os" in
    linux) echo "linux" ;;
    darwin) echo "darwin" ;;
    *) err "unsupported OS: $os (supported: linux, darwin)" ;;
  esac
}

detect_arch() {
  local arch
  arch="$(uname -m)"
  case "$arch" in
    x86_64|amd64) echo "amd64" ;;
    arm64|aarch64) echo "arm64" ;;
    *) err "unsupported architecture: $arch (supported: amd64, arm64)" ;;
  esac
}

fetch_latest_tag() {
  local tag
  tag="$(curl -fsSL "$API_URL" | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n1)"
  [ -n "$tag" ] || err "unable to determine latest release tag"
  echo "$tag"
}

install_binary() {
  local os arch tag version archive url tmpdir
  os="$(detect_os)"
  arch="$(detect_arch)"

  need_cmd curl
  need_cmd tar

  tag="$(fetch_latest_tag)"
  version="${tag#v}"
  archive="${BIN_NAME}_${version}_${os}_${arch}.tar.gz"
  url="https://github.com/${REPO}/releases/download/${tag}/${archive}"

  tmpdir="$(mktemp -d)"
  trap 'rm -rf "$tmpdir"' EXIT

  log "Installing ${BIN_NAME} ${tag} for ${os}/${arch}"
  log "Downloading ${url}"

  curl -fL "$url" -o "$tmpdir/$archive" || err "failed to download release archive"
  tar -xzf "$tmpdir/$archive" -C "$tmpdir" || err "failed to extract archive"

  [ -f "$tmpdir/$BIN_NAME" ] || err "binary not found in archive"

  chmod +x "$tmpdir/$BIN_NAME"

  if [ -w "$INSTALL_DIR" ]; then
    mv "$tmpdir/$BIN_NAME" "$INSTALL_DIR/$BIN_NAME"
  else
    log "Installing to ${INSTALL_DIR} requires elevated permissions"
    sudo mv "$tmpdir/$BIN_NAME" "$INSTALL_DIR/$BIN_NAME"
  fi

  if ! command -v "$BIN_NAME" >/dev/null 2>&1; then
    err "installation completed but ${BIN_NAME} is not in PATH"
  fi

  log "${BIN_NAME} installed successfully: $(command -v "$BIN_NAME")"
  "$BIN_NAME" --version || true
}

install_binary
