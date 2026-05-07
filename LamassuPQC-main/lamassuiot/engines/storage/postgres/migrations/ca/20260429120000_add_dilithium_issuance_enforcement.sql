-- +goose Up
-- +goose StatementBegin
ALTER TABLE issuance_profiles
	ADD COLUMN crypto_enforcement_allow_dilithium_keys boolean NOT NULL DEFAULT true,
	ADD COLUMN crypto_enforcement_allowed_dilithium_modes text DEFAULT '{}';
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE issuance_profiles
	DROP COLUMN IF EXISTS crypto_enforcement_allowed_dilithium_modes,
	DROP COLUMN IF EXISTS crypto_enforcement_allow_dilithium_keys;
-- +goose StatementEnd
