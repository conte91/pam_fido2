#include "Assertion.h"

#include <cstring>

namespace Assertion {

Assertion::Assertion(const fido_assert_t* cred, size_t idx) {
	/* Display name might be NULL. */
	const char* dn = fido_assert_user_display_name(cred, idx);
	if (dn) {
		display_name = std::make_shared<std::string>(dn);
	} else {
		display_name = nullptr;
	}
	/*
	 * User name might be NULL, if this credential is not a resident key
	 * (FIDO2) credential.
	 */
	const char* un = fido_assert_user_name(cred, idx);
	if (un) {
		user_name = std::make_shared<std::string>(un);
	} else {
		user_name = nullptr;
	}
	auto auth_ptr = fido_assert_authdata_ptr(cred, idx);
	auto auth_len = fido_assert_authdata_len(cred, idx);
	auth_data = AuthData{std::string(auth_ptr, auth_ptr + auth_len)};
}

std::vector<Assertion> Assertion::parseGetAssertionResponse(const fido_assert_t* assert) {
	std::vector<Assertion> result = {};
	size_t n_asserts = fido_assert_count(assert);
	for (size_t i = 0; i < n_asserts; ++i) {
		result.push_back(Assertion(assert, i));
	}
	return result;
}

static size_t _parseAttestedCredData(AttestedCredData* att, const std::string& data) {
	size_t len = data.size();
	size_t len_remaining = len;
	if (len < 18) {
		throw std::runtime_error("Attempted to parse credential data of length < 18 (len: " + std::to_string(len) + ").");
	}
	uint8_t* pos = (uint8_t*)data.data();
	memcpy(att->aaguid.data(), pos, 16);
	pos += 16;
	len_remaining -= 16;

	/* Length is stored big endian. */
	uint16_t cred_len = *pos++;
	cred_len <<= 8;
	cred_len |= *pos++;
	len_remaining -= 2;
	if (cred_len > len_remaining) {
		throw std::runtime_error("No space left for credential of length " + std::to_string(cred_len) + " (remaining bytes: " + std::to_string(len_remaining) + ").");
	}
	att->cred_id.assign((const char*)pos, cred_len);
	pos += cred_len;
	return (char *)pos - data.data();
}

AttestedCredData::AttestedCredData(const std::string& data) {
	(void)_parseAttestedCredData(this, data);
}

AuthData::AuthData(const std::string& data) {
	size_t len = data.size();
	size_t len_remaining = len;

	static constexpr int FLAGS_UP = 1 << 0;
	static constexpr int FLAGS_UV = 1 << 2;
	static constexpr int FLAGS_ATT_DATA_PRESENT = 1 << 6;
	static constexpr int FLAGS_EXT_DATA_PRESENT = 1 << 7;

	if (len < 37) {
		throw std::runtime_error("Attempted to parse authenticator data of length < 37 (len: " + std::to_string(len) + ").");
	}
	uint8_t* pos = (uint8_t*)data.data();
	memcpy(rp_id_hash.data(), pos, 32);
	pos += 32;
	len_remaining -= 32;

	uint8_t flags = *pos++;
	user_present = flags & FLAGS_UP;
	user_verified = flags & FLAGS_UV;
	bool att_data_present = flags & FLAGS_ATT_DATA_PRESENT;
	bool ext_data_present = flags & FLAGS_EXT_DATA_PRESENT;
	/* TODO */
	(void)ext_data_present;
	sign_count = 0;
	for (int i = 0; i < 4; ++i) {
		sign_count = (sign_count << 8) + *pos++;
	}
	len_remaining -= 4;
	if (att_data_present) {
		cred_data = std::make_shared<AttestedCredData>();
		pos += _parseAttestedCredData(cred_data.get(), data.substr((char *)pos - data.data()));
	}
}

}
