#!/bin/bash
# Simple regression harness for frdpd server
#
# This script illustrates how to run a basic regression test against the
# frdpd daemon. In a CI environment you should replace the placeholders
# with real user credentials and automate the assertions.

set -euo pipefail

SERVER_ADDR="${SERVER_ADDR:-127.0.0.1}"
SERVER_PORT="${SERVER_PORT:-3389}"
USER="${USER:-testuser}"
PASSWORD="${PASSWORD:-password}"

function log() {
    echo "[regression] $*"
}

log "Starting regression tests against ${SERVER_ADDR}:${SERVER_PORT}"

# Test 1: Plain NLA authentication using password
log "Test 1: NLA password authentication"
# TODO: replace with real xfreerdp invocation once available in CI
# Example: xfreerdp /u:"$USER" /p:"$PASSWORD" /v:"${SERVER_ADDR}:${SERVER_PORT}" /cert-ignore +clipboard

log "Test 1 complete"

# Test 2: Kerberos authentication
log "Test 2: Kerberos authentication"
# Ensure you have a valid Kerberos ticket before running this test (kinit)
# TODO: call xfreerdp with /gu:${USER} /p:(empty) to use Kerberos
log "Test 2 complete"

# Test 3: Session reconnection
log "Test 3: Reconnection"
# TODO: connect, disconnect and reconnect and assert the session is reused
log "Test 3 complete"

log "All regression tests completed"
