#!/usr/bin/env bash
# bin/host-audit.sh — backwards-compatible shim. The audit lives in bin/system-scan.sh.
exec bash "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/system-scan.sh" "$@"
