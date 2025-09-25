#!/usr/bin/env sh
set -euo pipefail

DEFAULT_TEMPLATE="/etc/bpst/config.template.json"
DEFAULT_OUTPUT="/etc/bpst/deployment.json"

render_config() {
  local template="${BPST_CONFIG_TEMPLATE:-}" output="${BPST_CONFIG_OUTPUT:-}" tmp

  if [ -z "$template" ] && [ -f "$DEFAULT_TEMPLATE" ]; then
    template="$DEFAULT_TEMPLATE"
  fi

  if [ -z "$template" ]; then
    return 0
  fi

  if [ -z "$output" ]; then
    if [ -n "${BPST_CONFIG:-}" ]; then
      output="$BPST_CONFIG"
    else
      output="$DEFAULT_OUTPUT"
    fi
  fi

  mkdir -p "$(dirname "$output")"

  export BPST_ADVERTISE_IP="${BPST_ADVERTISE_IP:-127.0.0.1}"
  export BPST_BOOTSTRAP_IP="${BPST_BOOTSTRAP_IP:-$BPST_ADVERTISE_IP}"

  tmp="$(mktemp)"
  envsubst <"$template" >"$tmp"
  mv "$tmp" "$output"
  chmod 644 "$output"

  BPST_CONFIG="$output"
  export BPST_CONFIG
  echo "[entrypoint] rendered deployment config to $output"
}

render_config

if [ "$#" -gt 0 ]; then
  case "$1" in
    bpst|deploy|node|user|observer)
      exec bpst "$@"
      ;;
  esac
fi

if [ -n "${BPST_CONFIG:-}" ] && [ -f "$BPST_CONFIG" ]; then
  exec bpst deploy "$BPST_CONFIG"
fi

if [ -n "${BPST_ROLE:-}" ]; then
  case "$BPST_ROLE" in
    node)
      : "${BPST_NODE_ID:?需要设置 BPST_NODE_ID}"
      : "${BPST_HOST:?需要设置 BPST_HOST}"
      : "${BPST_PORT:?需要设置 BPST_PORT}"
      CHUNK_SIZE="${BPST_CHUNK_SIZE:-1024}"
      STORAGE_KB="${BPST_STORAGE_KB:-2048}"
      BOBTAIL_K="${BPST_BOBTAIL_K:-3}"
      BOOTSTRAP_DEFAULT="${BPST_BOOTSTRAP_IP}:62000"
      BOOTSTRAP="${BPST_BOOTSTRAP:-$BOOTSTRAP_DEFAULT}"
      STORAGE_BYTES=$((STORAGE_KB * 1024))
      exec bpst node "$BPST_NODE_ID" "$BPST_HOST" "$BPST_PORT" "$BOOTSTRAP" "$CHUNK_SIZE" "$STORAGE_BYTES" "$BOBTAIL_K"
      ;;
    user)
      : "${BPST_USER_ID:?需要设置 BPST_USER_ID}"
      : "${BPST_HOST:?需要设置 BPST_HOST}"
      : "${BPST_PORT:?需要设置 BPST_PORT}"
      BOOTSTRAP_DEFAULT="${BPST_BOOTSTRAP_IP}:62000"
      BOOTSTRAP="${BPST_BOOTSTRAP:-$BOOTSTRAP_DEFAULT}"
      exec bpst user "$BPST_USER_ID" "$BPST_HOST" "$BPST_PORT" "$BOOTSTRAP"
      ;;
    observer)
      : "${BPST_OBSERVER_ID:?需要设置 BPST_OBSERVER_ID}"
      : "${BPST_HOST:?需要设置 BPST_HOST}"
      : "${BPST_PORT:?需要设置 BPST_PORT}"
      BOOTSTRAP_DEFAULT="${BPST_BOOTSTRAP_IP}:62000"
      BOOTSTRAP="${BPST_BOOTSTRAP:-$BOOTSTRAP_DEFAULT}"
      exec bpst observer "$BPST_OBSERVER_ID" "$BPST_HOST" "$BPST_PORT" "$BOOTSTRAP"
      ;;
    *)
      echo "未知的 BPST_ROLE: $BPST_ROLE" >&2
      exit 1
      ;;
  esac
fi

exec bpst "$@"
