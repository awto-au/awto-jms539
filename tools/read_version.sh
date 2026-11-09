#!/bin/bash
set -euo pipefail
# Read the running firmware version from a JMicron JMS539(B) USB-SATA bridge.
# Uses the vendor SCSI command E0 F4 E7 (read-only: no code execution, no flash writes).
#
# Usage: sudo ./read_version.sh /dev/sgN
#   Find the right sg node with: lsscsi -g   (the JMicron "USB to ATA/ATAPI Bridge")

DEV="${1:?usage: read_version.sh /dev/sgN}"
OUT="$(mktemp)"
trap 'rm -f "$OUT"' EXIT

# CDB padded to the 6-byte minimum sg_raw requires; firmware only matches the first 3 bytes.
sudo sg_raw -b -r 16 -o "$OUT" "$DEV" e0 f4 e7 00 00 00 >/dev/null

hex=$(xxd -p "$OUT")
echo "raw:     $hex"
# Layout: F4 E7 | VID(2) PID(2) | 00 00 | prod(4) | version(4)
vid=${hex:4:4}; pid=${hex:8:4}
v=$((16#${hex:24:2})); a=$((16#${hex:26:2})); b=$((16#${hex:28:2})); c=$((16#${hex:30:2}))
printf 'VID:PID: %s:%s\n' "$vid" "$pid"
printf 'FW:      %02d.%02d.%02d.%02d\n' "$v" "$a" "$b" "$c"
