#!/usr/bin/env bash
# Packages, installs, approves and commits the three ShurokkhaNet contracts.
# Written against the peer CLI rather than network.sh deployCC, because
# deployCC does not install on the third organisation.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$HERE/env.sh"
ROOT="$(cd "$HERE/../.." && pwd)"

COLLECTIONS="${COLLECTIONS:-$ROOT/network/collections/assertion_collections.json}"
SEQ="${SEQ:-1}"
VER="${VER:-1.0}"

deployOne() {
  local name=$1 path=$2 collections=${3:-}

  echo "==> vendoring $name"
  ( cd "$path" && GOFLAGS=-mod=mod go mod tidy && go mod vendor )

  echo "==> packaging $name"
  peer lifecycle chaincode package "/tmp/$name.tar.gz" \
    --path "$path" --lang golang --label "${name}_${VER}"

  for org in 1 2 3; do
    useOrg $org
    echo "==> installing $name on Org${org}"
    peer lifecycle chaincode install "/tmp/$name.tar.gz" 2>&1 | tail -1
  done

  useOrg 1
  local pkgid
  pkgid=$(peer lifecycle chaincode queryinstalled --output json \
    | python3 -c "import sys,json;print([p['package_id'] for p in json.load(sys.stdin)['installed_chaincodes'] if p['label']=='${name}_${VER}'][0])")
  echo "==> package id $pkgid"

  local cflag=()
  [ -n "$collections" ] && cflag=(--collections-config "$collections")

  for org in 1 2 3; do
    useOrg $org
    echo "==> approving $name for Org${org}"
    peer lifecycle chaincode approveformyorg \
      -o "$ORDERER_ADDR" --ordererTLSHostnameOverride "$ORDERER_HOSTNAME" --tls --cafile "$ORDERER_CA" \
      --channelID "$CHANNEL_NAME" --name "$name" --version "$VER" --package-id "$pkgid" \
      --sequence "$SEQ" "${cflag[@]}" >/dev/null
  done

  useOrg 1
  echo "==> committing $name"
  # shellcheck disable=SC2046
  peer lifecycle chaincode commit \
    -o "$ORDERER_ADDR" --ordererTLSHostnameOverride "$ORDERER_HOSTNAME" --tls --cafile "$ORDERER_CA" \
    --channelID "$CHANNEL_NAME" --name "$name" --version "$VER" --sequence "$SEQ" \
    "${cflag[@]}" $(peerAddrs) >/dev/null
  echo "==> $name committed"
  echo
}

deployOne assertion-cc "$ROOT/chaincode/assertion" "$COLLECTIONS"
deployOne audit-cc     "$ROOT/chaincode/audit"
deployOne signal-cc    "$ROOT/chaincode/signal"

echo "All three contracts are live on '$CHANNEL_NAME'."
