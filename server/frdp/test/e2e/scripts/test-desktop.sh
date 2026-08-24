#!/usr/bin/env bash
set -Eeuo pipefail

children=()
desktop_pid=

cleanup()
{
	local pid=
	trap - TERM INT EXIT
	if [[ -n $desktop_pid ]]; then
		kill -TERM -- "-$desktop_pid" 2>/dev/null || kill -TERM "$desktop_pid" 2>/dev/null || true
	fi
	for pid in "${children[@]}"; do
		kill -TERM "$pid" 2>/dev/null || true
	done
	if [[ -n $desktop_pid ]]; then
		wait "$desktop_pid" 2>/dev/null || true
	fi
	for pid in "${children[@]}"; do
		wait "$pid" 2>/dev/null || true
	done
}

trap 'cleanup; exit 143' TERM INT
trap cleanup EXIT

installed_desktop=$(</etc/frdp-test-desktop-type)
desktop_type=${FRDP_DESKTOP_TYPE:-$installed_desktop}
desktop_window_manager=()
if [[ $desktop_type != "$installed_desktop" ]]; then
	printf 'requested desktop %s is not installed; image contains %s\n' \
		"$desktop_type" "$installed_desktop" >&2
	exit 64
fi

case "$desktop_type" in
	openbox)
		desktop_name=Openbox
		desktop_command=(openbox --sm-disable)
		;;
	xfce)
		desktop_name=XFCE
		desktop_command=(xfce4-session)
		;;
	mate)
		desktop_name=MATE
		desktop_command=(mate-session)
		;;
	lxqt)
		desktop_name=LXQt
		desktop_command=(startlxqt)
		desktop_window_manager=(openbox --sm-disable)
		;;
	plasma)
		desktop_name=KDE
		desktop_command=(startplasma-x11)
		;;
	gnome)
		desktop_name=GNOME
		desktop_command=(gnome-session --session=gnome)
		;;
	*)
		printf 'unsupported FRDP_DESKTOP_TYPE: %s\n' "$desktop_type" >&2
		exit 64
		;;
esac

export DESKTOP_SESSION="$desktop_type"
export GDK_BACKEND=x11
export LIBGL_ALWAYS_SOFTWARE=1
export NO_AT_BRIDGE=1
export QT_QPA_PLATFORM=xcb
export XDG_CURRENT_DESKTOP="$desktop_name"
export XDG_SESSION_DESKTOP="$desktop_type"
export XDG_SESSION_TYPE=x11

xsetroot -solid '#243447'
if ((${#desktop_window_manager[@]} > 0)); then
	"${desktop_window_manager[@]}" &
	children+=("$!")
fi
setsid dbus-run-session -- "${desktop_command[@]}" &
desktop_pid=$!

for ((i = 0; i < 300; i++)); do
	xprop -root _NET_SUPPORTING_WM_CHECK 2>/dev/null | grep -q 'window id' && break
	if ! kill -0 "$desktop_pid" 2>/dev/null; then
		wait "$desktop_pid" || status=$?
		printf '%s desktop exited before its window manager became ready (status=%s)\n' \
			"$desktop_type" "${status:-0}" >&2
		exit 1
	fi
	sleep 0.1
done
xprop -root _NET_SUPPORTING_WM_CHECK 2>/dev/null | grep -q 'window id' || {
	printf '%s desktop did not publish a window manager within 30 seconds\n' \
		"$desktop_type" >&2
	exit 1
}
xprop -root -f _FRDP_TEST_DESKTOP_TYPE 8s \
	-set _FRDP_TEST_DESKTOP_TYPE "$desktop_type"

xterm -title 'FRDP Test Desktop' -geometry 92x26+48+48 -hold \
	-e /bin/sh -c 'printf "FreeRDP Docker test desktop\n\nType: %s\nUser: %s\nDisplay: %s\n\nThe RDP framebuffer and input path are active.\n" "$FRDP_DESKTOP_TYPE" "$USER" "$DISPLAY"' \
	>/dev/null 2>&1 &
children+=("$!")

xclock -digital -update 1 -geometry 260x80-48+48 -title 'FRDP Test Clock' \
	>/dev/null 2>&1 &
children+=("$!")

wait "$desktop_pid"
