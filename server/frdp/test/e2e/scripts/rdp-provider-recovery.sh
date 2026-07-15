#!/usr/bin/env bash
set -Eeuo pipefail

FRDP_E2E_CONTROL_DIR=${FRDP_E2E_CONTROL_DIR:-/run/frdp-e2e-control}
FRDP_ARTIFACT_DIR=${FRDP_ARTIFACT_DIR:-/artifacts}

mkdir -p "$FRDP_ARTIFACT_DIR" "$FRDP_E2E_CONTROL_DIR"
mkdir -p "$FRDP_ARTIFACT_DIR/provider-sesmand-crash" \
	"$FRDP_ARTIFACT_DIR/provider-post-recovery"
chmod 0777 "$FRDP_ARTIFACT_DIR/provider-sesmand-crash" \
	"$FRDP_ARTIFACT_DIR/provider-post-recovery"

bash /opt/frdp-e2e/scripts/rdp-probe.sh

: >"$FRDP_E2E_CONTROL_DIR/arm-sesmand-crash"
FRDP_ARTIFACT_DIR="$FRDP_ARTIFACT_DIR/provider-sesmand-crash" \
	FRDP_SESSION_EXPECT_MANAGER_CRASH=1 \
	bash /opt/frdp-e2e/scripts/rdp-session-smoke.sh

FRDP_ARTIFACT_DIR="$FRDP_ARTIFACT_DIR/provider-post-recovery" \
	bash /opt/frdp-e2e/scripts/rdp-session-smoke.sh

printf 'provider=samba-ad-sssd\nhelper=frdp-sesmand\nactive_session_crash=pass\npost_recovery_session=pass\n' \
	>"$FRDP_ARTIFACT_DIR/provider-recovery.txt"
