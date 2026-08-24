#!/usr/bin/env bash
set -Eeuo pipefail

children=()

cleanup()
{
	local pid=
	trap - TERM INT EXIT
	for pid in "${children[@]}"; do
		kill -TERM "$pid" 2>/dev/null || true
	done
	for pid in "${children[@]}"; do
		wait "$pid" 2>/dev/null || true
	done
}

trap 'cleanup; exit 143' TERM INT
trap cleanup EXIT

xsetroot -solid '#243447'
openbox --sm-disable >/dev/null 2>&1 &
children+=("$!")

for ((i = 0; i < 100; i++)); do
	xprop -root _NET_SUPPORTING_WM_CHECK 2>/dev/null | grep -q 'window id' && break
	sleep 0.1
done
xprop -root _NET_SUPPORTING_WM_CHECK 2>/dev/null | grep -q 'window id'

xterm -title 'FRDP Test Desktop' -geometry 92x26+48+48 -hold \
	-e /bin/sh -c 'printf "FreeRDP Docker test desktop\n\nUser: %s\nDisplay: %s\n\nThe RDP framebuffer and input path are active.\n" "$USER" "$DISPLAY"' \
	>/dev/null 2>&1 &
children+=("$!")

xclock -digital -update 1 -geometry 260x80-48+48 -title 'FRDP Test Clock' \
	>/dev/null 2>&1 &
children+=("$!")

wait "${children[0]}"
