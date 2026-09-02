#!/usr/bin/env bash
# Brings up a three-organisation ShurokkhaNet network on the fabric-samples
# test-network: MFS-A, MFS-B and the oversight member (BFIU / Bangladesh Bank).
#
# The whitepaper prototype (Section 10) describes four organisations and RAFT
# across three. What runs here is three organisations with the same trust
# separation; the fourth (a mobile operator) is added with the same addOrg
# pattern and is Phase 2 on the roadmap. Say that plainly rather than implying
# the demo is the full network.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$HERE/env.sh"

cd "$TN"
./network.sh down || true
./network.sh up createChannel -c "$CHANNEL_NAME" -ca -s couchdb

cd "$TN/addOrg3"
./addOrg3.sh up -c "$CHANNEL_NAME" -ca -s couchdb

echo
echo "Channel '$CHANNEL_NAME' is up with Org1 (MFS-A), Org2 (MFS-B) and Org3 (oversight)."
echo "Next: ./deploy.sh"
