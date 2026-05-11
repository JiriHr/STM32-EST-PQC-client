#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# ML-DSA EST Setup Script
# ==============================================================================

DEFAULT_BASE="http://127.0.0.1:8080"

echo "ML-DSA EST Setup"
echo

# ==============================================================================
# BASE URL Selection
# ==============================================================================

echo "Default BASE URL:"
echo "$DEFAULT_BASE"
echo

read -r -p "Use this BASE URL? [y/N]: " USE_DEFAULT_BASE

case "$USE_DEFAULT_BASE" in
  y|Y|yes|YES)
    BASE="$DEFAULT_BASE"
    ;;
  *)
    read -r -p "Enter BASE URL: " BASE

    if [[ -z "$BASE" ]]; then
      echo "ERROR: BASE URL cannot be empty"
      exit 1
    fi
    ;;
esac

echo

# ==============================================================================
# Algorithm Selection
# ==============================================================================

echo "Choose ML-DSA algorithm:"
echo "1) ML-DSA-44"
echo "2) ML-DSA-65"
echo "3) ML-DSA-87"
echo

read -r -p "Enter choice [1-3]: " ALG_CHOICE

case "$ALG_CHOICE" in
  1|44)
    ALG="44"
    ;;
  2|65)
    ALG="65"
    ;;
  3|87)
    ALG="87"
    ;;
  *)
    echo "ERROR: Invalid algorithm choice. Use 1, 2, 3, 44, 65, or 87."
    exit 1
    ;;
esac

KEY_TYPE="ML-DSA-${ALG}"
CA_ID="mldsa${ALG}-est-ca"
DMS_ID="mldsa${ALG}-est-dms"

echo
echo "Using configuration:"
echo "BASE=$BASE"
echo "ALG=$ALG"
echo "KEY_TYPE=$KEY_TYPE"
echo "CA_ID=$CA_ID"
echo "DMS_ID=$DMS_ID"
echo

read -r -p "Continue with this configuration? [y/N]: " CONFIRM

case "$CONFIRM" in
  y|Y|yes|YES)
    ;;
  *)
    echo "Aborted."
    exit 0
    ;;
esac

echo

# Check dependencies
if ! command -v curl >/dev/null 2>&1; then
  echo "ERROR: curl is not installed"
  exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "ERROR: jq is not installed"
  exit 1
fi

# ==============================================================================
# CA Profile Creation
# ==============================================================================

echo "Creating CA profile..."

PROFILE_ID="$(
  curl -sS -X POST "$BASE/api/ca/v1/profiles" \
    -H "Content-Type: application/json" \
    -d "{
      \"name\": \"mldsa${ALG}-est-device-profile\",
      \"description\": \"EST profile for ML-DSA-${ALG} STM enrollment\",
      \"validity\": {
        \"type\": \"Duration\",
        \"duration\": \"1h\"
      },
      \"crypto_enforcement\": {
        \"enabled\": true,
        \"allow_mldsa_keys\": true,
        \"allowed_mldsa_security_versions\": [$ALG]
      }
    }" | jq -r '.id'
)"

if [[ -z "$PROFILE_ID" || "$PROFILE_ID" == "null" ]]; then
  echo "ERROR: Failed to create CA profile or extract PROFILE_ID"
  exit 1
fi

echo "PROFILE_ID=$PROFILE_ID"
echo

# ==============================================================================
# CA Creation
# ==============================================================================

echo "Creating CA..."

curl -sS -X POST "$BASE/api/ca/v1/cas" \
  -H "Content-Type: application/json" \
  -d "{
    \"id\": \"$CA_ID\",
    \"key_metadata\": {
      \"type\": \"$KEY_TYPE\",
      \"bits\": 0
    },
    \"subject\": {
      \"common_name\": \"ML-DSA-${ALG} EST CA\"
    },
    \"ca_expiration\": {
      \"type\": \"Duration\",
      \"duration\": \"24h\"
    },
    \"profile_id\": \"$PROFILE_ID\",
    \"metadata\": {
      \"poc\": true,
      \"algorithm\": \"ML-DSA-${ALG}\"
    }
  }" | jq .

echo

# ==============================================================================
# DMS Manager Creation
# ==============================================================================

echo "Creating DMS..."

curl -sS -X POST "$BASE/api/dmsmanager/v1/dms" \
  -H "Content-Type: application/json" \
  -d "{
    \"id\": \"$DMS_ID\",
    \"name\": \"ML-DSA-${ALG} EST STM Test\",
    \"metadata\": {
      \"poc\": true,
      \"algorithm\": \"ML-DSA-${ALG}\"
    },
    \"settings\": {
      \"enrollment_settings\": {
        \"protocol\": \"EST_RFC7030\",
        \"est_rfc7030_settings\": {
          \"auth_mode\": \"NO_AUTH\"
        },
        \"device_provisioning_profile\": {
          \"icon\": \"Cpu\",
          \"icon_color\": \"#355C7D\",
          \"metadata\": {
            \"poc\": true,
            \"algorithm\": \"ML-DSA-${ALG}\"
          },
          \"tags\": [
            \"pqc\",
            \"est\",
            \"mldsa${ALG}\"
          ]
        },
        \"enrollment_ca\": \"$CA_ID\",
        \"registration_mode\": \"JITP\",
        \"enable_replaceable_enrollment\": true,
        \"verify_csr_signature\": true
      },
      \"reenrollment_settings\": {
        \"additional_validation_cas\": [],
        \"reenrollment_delta\": \"1m\",
        \"enable_expired_renewal\": true,
        \"preventive_delta\": \"10m\",
        \"critical_delta\": \"5m\"
      },
      \"ca_distribution_settings\": {
        \"include_enrollment_ca\": true
      },
      \"issuance_profile_id\": \"$PROFILE_ID\"
    }
  }" | jq .

echo

# ==============================================================================
# EST Enroll URL
# ==============================================================================

ENROLL_URL="$BASE/api/dmsmanager/.well-known/est/$DMS_ID/simpleenroll"

echo "Done."
echo
echo "EST enroll URL:"
echo "$ENROLL_URL"