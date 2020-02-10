#include "Authenticator.h"

#include <iostream>

#include "hex.h"
#include "HostId.h"
#include "UserId.h"

static void _delete_dev(fido_dev_t* dev) {
	fido_dev_free(&dev);
};

static std::array<unsigned char, 32> get_clientdata_hash() {
	std::array<unsigned char, 32> result;
	for (int i = 0; i < 32; ++i) {
		/* TODO */
		result[i] = i;
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

Authenticator::Authenticator(const fido_dev_info_t* dev) :
	_dev(_open_dev(dev)) {

}

bool Authenticator::authenticate(const KeyStore& keystore, bool include_allow_list) {
	auto delete_assert = [](fido_assert_t* assert) {
		fido_assert_free(&assert);
	};
	std::unique_ptr<fido_assert_t, decltype(delete_assert)> assert(fido_assert_new(), delete_assert);
	if (!assert) {
		throw std::runtime_error("fido_assert_new() failed.\n");
	}
	auto allowed_keys = keystore.list_keys();
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
		std::cerr << "Failed to set UP flag: " << fido_strerr(r) << "\n";
		return false;
	}
	r = fido_assert_set_uv(assert.get(), FIDO_OPT_TRUE);
	if (r != FIDO_OK) {
		std::cerr << "Failed to set UV flag: " << fido_strerr(r) << "\n";
		return false;
	}
	r = fido_assert_set_rp(assert.get(), "ttclabs.me");
	if (r != FIDO_OK) {
		std::cerr << "Failed to set client data hash: " << fido_strerr(r) << "\n";
		return false;
	}
	r = fido_assert_set_clientdata_hash(assert.get(), get_clientdata_hash().data(), 32);
	if (r != FIDO_OK) {
		std::cerr << "Failed to set client data hash: " << fido_strerr(r) << "\n";
		return false;
	}
	if (include_allow_list) {
		for (const auto& cred : allowed_keys) {
			r = fido_assert_allow_cred(assert.get(), (const unsigned char*)cred.cred_id.data(), cred.cred_id.size());
			if (r != FIDO_OK) {
				std::cerr << "Failed to include credential: " << fido_strerr(r) << "\n";
				return false;
			}
		}
	}
	r = fido_dev_get_assert(_dev.get(), assert.get(), "XXXX");
	if (r != FIDO_OK) {
		std::cerr << "Failed to authenticate credential: " << fido_strerr(r) << "\n";
		return false;
	}
	//auto assertions = Assertion::Assertion::parseGetAssertionResponse(assert);
	//for (const auto& a : assertions) {
	for (int i = 0; i < fido_assert_count(assert.get()); ++i) {
		//auto cred_data = a.cred_data;
		//if (!cred_data) {
		//continue;
		//}
		//std::cout << "Key provided credential: " << Hex::encode(cred_data->cred_id) << "\n";
		for (auto& k : allowed_keys) {
			std::cout << "Attempting key" << Hex::encode(k.pubkey) << "\n";
			auto verify_result = fido_assert_verify(assert.get(), i, COSE_ES256 /* TODO */, k.pubkey.data()/*to_libfido2_key().get()*/);
			if (verify_result == FIDO_OK) {
			//if (a.verify(k)) {
				std::cout << "Authentication successful with credential ";
				std::cout << Hex::encode(k.cred_id) << ", sign count ";
				//std::cout << a.cred_data->sign_count << "\n";
				return true;
			}
		}
	}
	std::cout << "No valid credential found :(\n";
	return false;
}

StoredCredential Authenticator::make_credential(const HostId& host, const UserId& user, bool resident_key) {
	/* Make sure our credential object is freed on exit. */
	auto delete_cred = [](fido_cred_t* ptr) {
		fido_cred_free(&ptr);
	};
	std::unique_ptr<fido_cred_t, decltype(delete_cred)> credential(fido_cred_new(), delete_cred);
	fido_cred_t* cred_ptr = credential.get();

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
	r = fido_cred_set_rp(cred_ptr, host.domain_name.c_str(), host.name.c_str());
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
	r = fido_dev_make_cred(_dev.get(), cred_ptr,"XXXX");
	if (r != FIDO_OK) {
		throw std::runtime_error(std::string("Failed to register credential: ") + fido_strerr(r));
	}
	StoredCredential stored(credential.get());
	return stored;
}

std::vector<std::shared_ptr<fido_dev_t>> Authenticator::list_devs() {
	constexpr int max_devs = 128;
	auto delete_devlist = [max_devs](fido_dev_t* dev) {
		fido_dev_info_free(&dev, max_devs);
	};
	std::unique_ptr<fido_dev_t*, decltype(delete_devlist)> devlist(fido_dev_info_new(max_devs), delete_devlist);
	if (devlist) {
		throw std::runtime_error("fido_dev_info_new failed.\n");
	}
}
