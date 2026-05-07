-- +goose Up
ALTER TABLE issuance_profiles
	ADD COLUMN crypto_enforcement_allow_mldsa_keys boolean NOT NULL DEFAULT true,
	ADD COLUMN crypto_enforcement_allowed_mldsa_security_versions text DEFAULT '{}';

-- +goose Down
ALTER TABLE issuance_profiles
	DROP COLUMN IF EXISTS crypto_enforcement_allowed_mldsa_security_versions,
	DROP COLUMN IF EXISTS crypto_enforcement_allow_mldsa_keys;
