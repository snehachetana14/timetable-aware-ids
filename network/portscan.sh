#!/bin/bash
# portscan.sh - simulate a port-scanning attacker
# Usage from Mininet CLI:  room204_h3 bash network/portscan.sh 10.0.2.4
TARGET=${1:-10.0.2.4}
echo "[portscan] scanning $TARGET"
nmap -p 1-200 -T4 "$TARGET"
echo "[portscan] done"