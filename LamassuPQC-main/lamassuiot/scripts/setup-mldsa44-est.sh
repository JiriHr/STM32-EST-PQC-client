#!/usr/bin/env bash
set -euo pipefail

BASE="${BASE:-http://127.0.0.1:8080}"
ALG="${ALG:-44}"
KEY_TYPE="ML-DSA-${ALG}"
CA_ID="mldsa${ALG}-est-ca"
DMS_ID="mldsa${ALG}-est-dms"

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required" >&2
  exit 1
fi

echo "BASE=${BASE}"
echo "ALG=${ALG}"
echo "KEY_TYPE=${KEY_TYPE}"
echo "CA_ID=${CA_ID}"
echo "DMS_ID=${DMS_ID}"

PROFILE_JSON="$(
  curl -fsS -X POST "${BASE}/api/ca/v1/profiles" \
    -H "Content-Type: application/json" \
    -d "{
      \"name\": \"mldsa${ALG}-est-device-profile\",
      \"description\": \"EST profile for ML-DSA-${ALG} STM enrollment\",
      \"validity\": {\"type\": \"Duration\", \"duration\": \"1h\"},
      \"crypto_enforcement\": {
        \"enabled\": true,
        \"allow_mldsa_keys\": true,
        \"allowed_mldsa_security_versions\": [${ALG}]
      }
    }"
)"
PROFILE_ID="$(printf '%s' "${PROFILE_JSON}" | jq -r '.id // empty')"
if [ -z "${PROFILE_ID}" ]; then
  echo "failed to create issuance profile:" >&2
  printf '%s\n' "${PROFILE_JSON}" >&2
  exit 1
fi
echo "PROFILE_ID=${PROFILE_ID}"

curl -fsS -X POST "${BASE}/api/ca/v1/cas" \
  -H "Content-Type: application/json" \
  -d "{
    \"id\": \"${CA_ID}\",
    \"key_metadata\": {\"type\": \"${KEY_TYPE}\", \"bits\": 0},
    \"subject\": {\"common_name\": \"ML-DSA-${ALG} EST CA\"},
    \"ca_expiration\": {\"type\": \"Duration\", \"duration\": \"24h\"},
    \"profile_id\": \"${PROFILE_ID}\",
    \"metadata\": {\"poc\": true, \"algorithm\": \"ML-DSA-${ALG}\"}
  }" | jq .

curl -fsS -X POST "${BASE}/api/dmsmanager/v1/dms" \
  -H "Content-Type: application/json" \
  -d "{
    \"id\": \"${DMS_ID}\",
    \"name\": \"ML-DSA-${ALG} EST STM Test\",
    \"metadata\": {\"poc\": true, \"algorithm\": \"ML-DSA-${ALG}\"},
    \"settings\": {
      \"enrollment_settings\": {
        \"protocol\": \"EST_RFC7030\",
        \"est_rfc7030_settings\": {
          \"auth_mode\": \"NO_AUTH\"
        },
        \"device_provisioning_profile\": {
          \"icon\": \"Cpu\",
          \"icon_color\": \"#355C7D\",
          \"metadata\": {\"poc\": true, \"algorithm\": \"ML-DSA-${ALG}\"},
          \"tags\": [\"pqc\", \"est\", \"mldsa${ALG}\"]
        },
        \"enrollment_ca\": \"${CA_ID}\",
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
      \"issuance_profile_id\": \"${PROFILE_ID}\"
    }
  }" | jq .

echo "Verifying DMS exists..."
curl -fsS "${BASE}/api/dmsmanager/v1/dms/${DMS_ID}" | jq '.id, .settings.enrollment_settings.enrollment_ca'

echo "EST cacerts URL:"
echo "https://localhost:8443/api/dmsmanager/.well-known/est/${DMS_ID}/cacerts"
echo "EST simpleenroll URL:"
echo "https://localhost:8443/api/dmsmanager/.well-known/est/${DMS_ID}/simpleenroll"
