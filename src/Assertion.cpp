#include "Assertion.h"

#include <cstring>
#include <memory>

#include "hex.h"

static void _delete_cred(fido_cred_t* ptr) {
	fido_cred_free(&ptr);
};

typedef std::unique_ptr<fido_cred_t, decltype(&_delete_cred)> CredPtr;

static CredPtr _fido_cred_from_authdata(const std::string& data) {
	CredPtr credential(fido_cred_new(), &_delete_cred);
	fido_cred_set_authdata(credential.get(), (const unsigned char *)data.data(), data.size());
	return credential;
}

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
	//auto verify_status = fido_assert_verify(cred, idx);
	//verified = verify_status == FIDO_OK;
	auto auth_ptr = fido_assert_authdata_ptr(cred, idx);
	auto auth_len = fido_assert_authdata_len(cred, idx);
	//if (auth_ptr) {
	//this->cred_data = std::make_shared<AttestedCredData>(std::string(auth_ptr, auth_ptr + auth_len));
	//} else {
	//this->cred_data = nullptr;
	//}
}

std::vector<Assertion> Assertion::parseGetAssertionResponse(const fido_assert_t* assert) {
	std::vector<Assertion> result = {};
	size_t n_asserts = fido_assert_count(assert);
	for (size_t i = 0; i < n_asserts; ++i) {
		result.push_back(Assertion(assert, i));
	}
	return result;
}

AttestedCredData::AttestedCredData(const std::string& data) {
	auto credential = _fido_cred_from_authdata(data);
	auto ci_ptr = fido_cred_id_ptr(credential.get());
	auto ci_len = fido_cred_id_len(credential.get());
	std::string cid{ci_ptr, ci_ptr + ci_len};
	auto pubkey_ptr = fido_cred_pubkey_ptr(credential.get());
	auto pubkey_len = fido_cred_pubkey_len(credential.get());
	std::string pk{pubkey_ptr, pubkey_ptr + pubkey_len};
	_cred = Credential{cid, pk};

	//auto aaguid_ptr = fido_cred_aaguid_ptr(credential.get());
	//auto aaguid_len = fido_cred_aaguid_len(credential.get());
	//cred_id.assign(aaguid_ptr, aaguid_ptr + aaguid_len);
}

#if 0
AuthData::AuthData(const std::string& data) {
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
bool Assertion::verify(const Credential& cred) {
	if (!cred_data) {
		std::cout << "(No credential data)\n";
		return false;
	}
	auto credential = _fido_cred_from_authdata(data);
	fido_cred_set_id(credential.
	return fido_assert_verify(credential.get(), ) == FIDO_OK;
}
#endif

}
