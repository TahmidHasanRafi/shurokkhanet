#!/usr/bin/env bash
# End-to-end check straight from the peer CLI, with no backend in the way.
# Useful when something looks wrong in the console and you need to know which
# side is broken.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$HERE/env.sh"

ID="smoke-$(date +%s)"
CASE=$(python3 -c "import json,base64,time;print(base64.b64encode(json.dumps({'caseRef':'CMP-SMOKE','exactAmount':412500,'srcWallet':'01700000001','dstWallet':'01900000002','victimStatement':'OTP read out over the phone','reportedAt':int(time.time()),'fraudAt':int(time.time())-180}).encode()).decode())")

useOrg 1
echo "== MFS-A raises the alert =="
# shellcheck disable=SC2046
peer chaincode invoke -o "$ORDERER_ADDR" --ordererTLSHostnameOverride "$ORDERER_HOSTNAME" --tls --cafile "$ORDERER_CA" \
  -C "$CHANNEL_NAME" -n assertion-cc $(peerAddrs) \
  -c "{\"function\":\"RaiseAssertion\",\"Args\":[\"$ID\",\"c1aaaa\",\"c1bbbb\",\"BAND_100K_500K\",\"e3b0c442\",\"1\"]}" \
  --transient "{\"case\":\"$CASE\"}"
sleep 2

echo "== MFS-B checks the destination commitment =="
useOrg 2
peer chaincode query -C "$CHANNEL_NAME" -n assertion-cc -c "{\"function\":\"CheckCommitment\",\"Args\":[\"c1bbbb\"]}"

echo "== MFS-B can read the case file (it is in the collection) =="
peer chaincode query -C "$CHANNEL_NAME" -n assertion-cc -c "{\"function\":\"GetCaseFile\",\"Args\":[\"$ID\"]}"

echo "== everyone can verify the collection hash without the contents =="
useOrg 3
peer chaincode query -C "$CHANNEL_NAME" -n assertion-cc -c "{\"function\":\"VerifyCaseFile\",\"Args\":[\"$ID\"]}"

echo "== an MFS member is refused Tier 3 =="
useOrg 2
peer chaincode invoke -o "$ORDERER_ADDR" --ordererTLSHostnameOverride "$ORDERER_HOSTNAME" --tls --cafile "$ORDERER_CA" \
  -C "$CHANNEL_NAME" -n assertion-cc $(peerAddrs) \
  -c "{\"function\":\"EndorseT3\",\"Args\":[\"$ID\",\"BFIU reference 2026/0042\"]}" 2>&1 | tail -2 || true

echo
echo "smoke test finished for $ID"
