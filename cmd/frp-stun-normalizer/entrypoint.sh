#!/bin/sh
set -eu

ready_file=/tmp/frp-stun-normalizer.ready
rm -f "$ready_file"

frp-stun-normalizer --ready-file "$ready_file" "$@" &
normalizer_pid=$!

shutdown() {
  trap - INT TERM
  if [ "${frpc_pid:-}" ]; then
    kill -TERM "$frpc_pid" 2>/dev/null || true
    wait "$frpc_pid" 2>/dev/null || true
  fi
  kill -TERM "$normalizer_pid" 2>/dev/null || true
  wait "$normalizer_pid" 2>/dev/null || true
}

trap 'shutdown; exit 0' INT TERM

while [ ! -e "$ready_file" ]; do
  if ! kill -0 "$normalizer_pid" 2>/dev/null; then
    wait "$normalizer_pid"
    exit $?
  fi
  sleep 0.1
done

if ! kill -0 "$normalizer_pid" 2>/dev/null; then
  wait "$normalizer_pid"
  exit $?
fi

frpc -c /etc/frp/frpc.toml &
frpc_pid=$!

while kill -0 "$frpc_pid" 2>/dev/null && kill -0 "$normalizer_pid" 2>/dev/null; do
  sleep 1 &
  wait $!
done

shutdown
exit 1
