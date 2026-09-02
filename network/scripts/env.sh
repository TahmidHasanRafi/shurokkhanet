#!/usr/bin/env bash
# Shared environment for the ShurokkhaNet scripts.
# FABRIC_SAMPLES must point at a cloned hyperledger/fabric-samples.

set -euo pipefail

: "${FABRIC_SAMPLES:?set FABRIC_SAMPLES to your fabric-samples checkout}"
export TN="$FABRIC_SAMPLES/test-network"
export PATH="$FABRIC_SAMPLES/bin:$PATH"
export FABRIC_CFG_PATH="$FABRIC_SAMPLES/config"
export CORE_PEER_TLS_ENABLED=true

export CHANNEL_NAME="${CHANNEL_NAME:-shurokkhanet}"
export ORDERER_ADDR=localhost:7050
export ORDERER_HOSTNAME=orderer.example.com
export ORDERER_CA="$TN/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem"

# Consortium seat -> test-network organisation
#   Org1 = MFS-A (victim side)   Org2 = MFS-B (destination side)   Org3 = BFIU / Bangladesh Bank
useOrg() {
  local n=$1
  case "$n" in
    1) export CORE_PEER_LOCALMSPID=Org1MSP
       export CORE_PEER_ADDRESS=localhost:7051
       export CORE_PEER_TLS_ROOTCERT_FILE="$TN/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt"
       export CORE_PEER_MSPCONFIGPATH="$TN/organizations/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp" ;;
    2) export CORE_PEER_LOCALMSPID=Org2MSP
       export CORE_PEER_ADDRESS=localhost:9051
       export CORE_PEER_TLS_ROOTCERT_FILE="$TN/organizations/peerOrganizations/org2.example.com/peers/peer0.org2.example.com/tls/ca.crt"
       export CORE_PEER_MSPCONFIGPATH="$TN/organizations/peerOrganizations/org2.example.com/users/Admin@org2.example.com/msp" ;;
    3) export CORE_PEER_LOCALMSPID=Org3MSP
       export CORE_PEER_ADDRESS=localhost:11051
       export CORE_PEER_TLS_ROOTCERT_FILE="$TN/organizations/peerOrganizations/org3.example.com/peers/peer0.org3.example.com/tls/ca.crt"
       export CORE_PEER_MSPCONFIGPATH="$TN/organizations/peerOrganizations/org3.example.com/users/Admin@org3.example.com/msp" ;;
    *) echo "unknown org $n" >&2; return 1 ;;
  esac
}

peerAddrs() {
  echo "--peerAddresses localhost:7051 --tlsRootCertFiles $TN/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt \
        --peerAddresses localhost:9051 --tlsRootCertFiles $TN/organizations/peerOrganizations/org2.example.com/peers/peer0.org2.example.com/tls/ca.crt \
        --peerAddresses localhost:11051 --tlsRootCertFiles $TN/organizations/peerOrganizations/org3.example.com/peers/peer0.org3.example.com/tls/ca.crt"
}
