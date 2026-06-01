#!/usr/bin/env bash
set -euo pipefail

BANNED="ring|aws-lc-rs|aws-lc-sys|openssl|openssl-sys"

RESULT=$(cargo tree --edges normal 2>/dev/null \
    | grep -E "($BANNED)" || true)

if [ -n "$RESULT" ]; then
    echo "FFI audit FAILED — banned crate(s) found in normal dep closure:"
    echo "$RESULT"
    exit 1
fi
echo "FFI audit PASSED"
