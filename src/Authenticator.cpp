#include "Authenticator.h"

#include <cstring>
#include <iostream>
#include <random>
#include <sstream>

#include <fido.h>

#include "hex.h"
#include "HostId.h"
#include "UserId.h"

static void _delete_dev(fido_dev_t* dev) {
	/* If the device is already closed, this is a NOP. */
	fido_dev_close(dev);
	fido_dev_free(&dev);
};

/** Gets a random challenge for the authenticator. */
static std::array<unsigned char, 32> get_clientdata_hash() {
	std::random_device rd;
	size_t rand_size = sizeof(decltype(rd()));
	//std::cout << "Rand size: " << rand_size << "\n";

	std::array<unsigned char, 32> result;
	size_t n_fills = 32 / rand_size;
	size_t n_left = 32 % rand_size;
	for (size_t i = 0; i < n_fills; ++i) {
		auto rand_num = rd();
		memcpy(result.data() + i * rand_size, &rand_num, sizeof(rand_num));
	}
	if (n_left) {
		auto rand_num = rd();
		memcpy(result.data() + n_fills * rand_size, &rand_num, n_left);
	}
	return result;
}

static std::unique_ptr<fido_dev_t, decltype(&_delete_dev)> _open_dev(const fido_dev_info_t* dev) {

	std::unique_ptr<fido_dev_t, decltype(&_delete_dev)> result(fido_dev_new(), &_delete_dev);
	if (!result) {
		throw std::runtime_error("fido_dev_new() failed.\n");
	}

	auto dev_path = fido_dev_info_path(dev);
	if (fido_dev_open(result.get(), dev_path) != FIDO_OK) {
		throw std::runtime_error(std::string("Couldn't open ") + dev_path + "\n");
	}
	return result;
}

Authenticator::Authenticator(const fido_dev_info_t* dev, const HostId& host) :
	_dev{_open_dev(dev)},
	_pin{},
	_pin_cb{nullptr},
	_pin_cb_param{nullptr},
	_require_pin{false},
	_host(host) {
	auto delete_cbor_info = [](fido_cbor_info_t* c) {
		fido_cbor_info_free(&c);
	};
	/* Check whether the device supports PIN authentication */
	std::unique_ptr<fido_cbor_info_t, decltype(delete_cbor_info)> ci{
		fido_cbor_info_new(), delete_cbor_info
	};
	int result = fido_dev_get_cbor_info(_dev.get(), ci.get());
	if (result != FIDO_OK) {
		std::ostringstream err;
		err << "Failed to fetch device information: ";
		err << fido_strerr(result) << "\n";
		throw std::runtime_error(err.str());
	}
	char **option_names = fido_cbor_info_options_name_ptr(ci.get());
	const bool *option_values = fido_cbor_info_options_value_ptr(ci.get());
	size_t n_options = fido_cbor_info_options_len(ci.get());
	for (size_t i = 0; i < n_options; ++i) {
		if (!strcmp(option_names[i], "clientPin")) {
			_require_pin = option_values[i];
		}
	}
}

void Authenticator::set_pin_callback(std::function<std::string(void*)> cb, void*param) {
	_pin_cb = cb;
	_pin_cb_param = param;
}

static void _delete_assert(fido_assert_t* assert) {
	fido_assert_free(&assert);
};

Authenticator::Assertion Authenticator::run_get_assert_request(const std::vector<Credential>& allowed_keys, bool include_allow_list) {
	Authenticator::Assertion assert(fido_assert_new(), _delete_assert);
	if (!assert) {
		throw std::runtime_error("fido_assert_new() failed.\n");
	}

	if (_require_pin && _pin == "") {
		if (!_pin_cb) {
			throw std::runtime_error("Can't authenticate: A PIN is required.");
		}
		_pin = _pin_cb(_pin_cb_param);
	}

	/*
	 * Set the following values:
	 * -   type;
	 * -   client data hash;
	 * -   relying party;
	 * -   user attributes;
	 * -   list of excluded credential IDs;
	 * -   resident key and user verification attributes.
	 */
	auto r = fido_assert_set_up(assert.get(), FIDO_OPT_TRUE);
	if (r != FIDO_OK) {
		std::ostringstream err;
		err << "Failed to set UP flag: " << fido_strerr(r) << "\n";
		throw std::runtime_error(err.str());
	}
	r = fido_assert_set_uv(assert.get(), FIDO_OPT_TRUE);
	if (r != FIDO_OK) {
		std::ostringstream err;
		err << "Failed to set UV flag: " << fido_strerr(r) << "\n";
		throw std::runtime_error(err.str());
	}
	r = fido_assert_set_rp(assert.get(), _host.domain_name.c_str());
	if (r != FIDO_OK) {
		std::ostringstream err;
		err << "Failed to set client data hash: " << fido_strerr(r) << "\n";
		throw std::runtime_error(err.str());
	}
	r = fido_assert_set_clientdata_hash(assert.get(), get_clientdata_hash().data(), 32);
	if (r != FIDO_OK) {
		std::ostringstream err;
		err << "Failed to set client data hash: " << fido_strerr(r) << "\n";
		throw std::runtime_error(err.str());
	}
	if (include_allow_list) {
		for (const auto& cred : allowed_keys) {
			r = fido_assert_allow_cred(assert.get(), (const unsigned char*)cred.cred_id.data(), cred.cred_id.size());
			if (r != FIDO_OK) {
				std::ostringstream err;
				err << "Failed to include credential: " << fido_strerr(r) << "\n";
				throw std::runtime_error(err.str());
			}
		}
	}
	r = fido_dev_get_assert(_dev.get(), assert.get(), _require_pin ? _pin.c_str() : nullptr);

	if (r != FIDO_OK) {
		std::ostringstream err;
		err << "Failed to authenticate credential: " << fido_strerr(r) << "\n";
		throw std::runtime_error(err.str());
	}
	return assert;
}


bool Authenticator::verify_assertion(const Assertion& assert, const std::vector<Credential>& allowed_keys) {
	for (size_t i = 0; i < fido_assert_count(assert.get()); ++i) {
		for (auto& k : allowed_keys) {
			//std::cout << "Attempting key" << Hex::encode(k.pubkey) << "\n";
			auto verify_result = fido_assert_verify(assert.get(), i, COSE_ES256, k.pubkey.data());
			if (verify_result == FIDO_OK) {
				//std::cout << "Authentication successful with credential ";
				//std::cout << Hex::encode(k.cred_id) << ", sign count ";
				return true;
			}
		}
	}
	//std::cout << "No valid credential found :(\n";
	return false;
}

Authenticator::Assertion Authenticator::get_assertion() {
	return run_get_assert_request({}, false);
}

bool Authenticator::authenticate(const KeyStore& keystore, bool include_allow_list) {
	Assertion assert = include_allow_list ?
		run_get_assert_request(keystore.list_keys(), true) :
		get_assertion();
	return verify_assertion(assert, keystore.list_keys());
}

StoredCredential Authenticator::make_credential(const UserId& user, bool resident_key) {
	/* Make sure our credential object is freed on exit. */
	auto delete_cred = [](fido_cred_t* ptr) {
		fido_cred_free(&ptr);
	};
	std::unique_ptr<fido_cred_t, decltype(delete_cred)> credential(fido_cred_new(), delete_cred);
	fido_cred_t* cred_ptr = credential.get();

	if (_require_pin && _pin == "") {
		if (!_pin_cb) {
			throw std::runtime_error("Can't authenticate: A PIN is required.");
		}
		_pin = _pin_cb(_pin_cb_param);
	}

	/*
	 * Set the following values:
	 * -   type;
	 * -   client data hash;
	 * -   relying party;
	 * -   user attributes;
	 * -   list of excluded credential IDs;
	 * -   resident key and user verification attributes.
	 */
	auto r = fido_cred_set_type(cred_ptr, COSE_ES256);
	if (r != FIDO_OK) {
		throw std::runtime_error(std::string("Failed to set credential type: ") +
				fido_strerr(r));
	}
	r = fido_cred_set_clientdata_hash(cred_ptr, get_clientdata_hash().data(), 32);
	if (r != FIDO_OK) {
		throw std::runtime_error(std::string("Failed to set client data hash: ") + fido_strerr(r));
	}
	r = fido_cred_set_rp(cred_ptr, _host.domain_name.c_str(), _host.name.c_str());
	if (r != FIDO_OK) {
		throw std::runtime_error(std::string("Failed to set client data hash: ") + fido_strerr(r));
	}
	r = fido_cred_set_rk(cred_ptr, resident_key ? FIDO_OPT_TRUE : FIDO_OPT_FALSE);
	if (r != FIDO_OK) {
		throw std::runtime_error(std::string("Failed to set resident key option: ") + fido_strerr(r));
	}
	r = fido_cred_set_user(cred_ptr, (const unsigned char*)&user.user_id, sizeof(user.user_id), user.username.c_str(), user.display_name.c_str(), NULL);
	if (r != FIDO_OK) {
		throw std::runtime_error(std::string("Failed to set user option: ") + fido_strerr(r));
	}
	r = fido_dev_make_cred(_dev.get(), cred_ptr, _require_pin ? _pin.c_str() : nullptr);
	if (r != FIDO_OK) {
		throw std::runtime_error(std::string("Failed to register credential: ") + fido_strerr(r));
	}
	StoredCredential stored(credential.get());
	return stored;
}

