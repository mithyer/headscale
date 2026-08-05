#!/bin/sh
set -u

if [ "${RENEWED_LINEAGE:-}" != "/etc/letsencrypt/live/ts.886996007.xyz" ]; then
  exit 0
fi

if /usr/bin/docker container inspect mb17u-headscale-nginx \
  --format '{{.State.Running}}' 2>/dev/null | grep -qx true; then
  /usr/bin/docker kill --signal HUP mb17u-headscale-nginx >/dev/null
fi
