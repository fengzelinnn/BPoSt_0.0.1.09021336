#!/usr/bin/env sh
set -eu

if [ "$#" -gt 0 ]; then
  case "$1" in
    bpst)
      shift
      exec bpst "$@"
      ;;
    deploy|node|user|observer)
      exec bpst "$@"
      ;;
  esac
fi

if [ "${BPST_CONFIG:-}" != "" ]; then
  exec bpst deploy "$BPST_CONFIG"
fi

if [ "${BPST_ROLE:-}" != "" ]; then
  case "$BPST_ROLE" in
    node)
      : "${BPST_NODE_ID:?需要设置 BPST_NODE_ID}"
      : "${BPST_HOST:?需要设置 BPST_HOST}"
      : "${BPST_PORT:?需要设置 BPST_PORT}"
      CHUNK_SIZE="${BPST_CHUNK_SIZE:-1024}"
      STORAGE_KB="${BPST_STORAGE_KB:-2048}"
      BOBTAIL_K="${BPST_BOBTAIL_K:-3}"
      BOOTSTRAP="${BPST_BOOTSTRAP:-none}"
      STORAGE_BYTES=$((STORAGE_KB * 1024))
      exec bpst node "$BPST_NODE_ID" "$BPST_HOST" "$BPST_PORT" "$BOOTSTRAP" "$CHUNK_SIZE" "$STORAGE_BYTES" "$BOBTAIL_K"
      ;;
    user)
      : "${BPST_USER_ID:?需要设置 BPST_USER_ID}"
      : "${BPST_HOST:?需要设置 BPST_HOST}"
      : "${BPST_PORT:?需要设置 BPST_PORT}"
      BOOTSTRAP="${BPST_BOOTSTRAP:-127.0.0.1:62000}"
      exec bpst user "$BPST_USER_ID" "$BPST_HOST" "$BPST_PORT" "$BOOTSTRAP"
      ;;
    observer)
      : "${BPST_OBSERVER_ID:?需要设置 BPST_OBSERVER_ID}"
      : "${BPST_HOST:?需要设置 BPST_HOST}"
      : "${BPST_PORT:?需要设置 BPST_PORT}"
      BOOTSTRAP="${BPST_BOOTSTRAP:-127.0.0.1:62000}"
      exec bpst observer "$BPST_OBSERVER_ID" "$BPST_HOST" "$BPST_PORT" "$BOOTSTRAP"
      ;;
    *)
      echo "未知的 BPST_ROLE: $BPST_ROLE" >&2
      exit 1
      ;;
  esac
fi

exec bpst "$@"
