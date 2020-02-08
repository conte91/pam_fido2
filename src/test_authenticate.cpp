#include <algorithm>
#include <functional>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <memory>
#include <utility>
#include <vector>

#include <fido.h>

#include "Assertion.h"
#include "KeyStore.h"
#include "hex.h"
#include "StoredCredential.h"
#include "util.h"

StoredCredential global_cred;

static std::string dev_info_str(const fido_dev_info_t* di) {
	std::ostringstream result;
	result << fido_dev_info_path(di) << ": vendor=0x" <<
		std::hex << std::setfill('0') << std::setw(4) <<
		(uint16_t)fido_dev_info_vendor(di) <<
		(uint16_t)fido_dev_info_product(di) <<
		" (" << fido_dev_info_manufacturer_string(di) <<
		" " << fido_dev_info_product_string(di) << ")";
	return result.str();
}

static std::array<unsigned char, 32> get_clientdata_hash() {
	std::array<unsigned char, 32> result;
	for (int i = 0; i < 32; ++i) {
		/* TODO */
		result[i] = i;
	}
	return result;
}

static std::string dump_hex(const char* buf, size_t len) {
	std::ostringstream s;
	s << std::hex << std::setfill('0');
	for (decltype(len) i = 0; i < len; ++i) {
		s << (unsigned int)buf[i] << " ";
	}
	return s.str();
}

static std::string dump_hex(const std::string& buf) {
	return dump_hex(buf.data(), buf.size());
}

static StoredCredential _register_credential(std::shared_ptr<fido_dev_t> dev) {
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
	r = fido_cred_set_rp(cred_ptr, "ttclabs.me", "Computer di simo");
	if (r != FIDO_OK) {
		throw std::runtime_error(std::string("Failed to set client data hash: ") + fido_strerr(r));
	}
	r = fido_cred_set_rk(cred_ptr, FIDO_OPT_FALSE);
	if (r != FIDO_OK) {
		throw std::runtime_error(std::string("Failed to set resident key option: ") + fido_strerr(r));
	}
	r = fido_cred_set_user(cred_ptr, (const unsigned char*)"simo", 4, "simo", "Simone Baratta", NULL);
	if (r != FIDO_OK) {
		throw std::runtime_error(std::string("Failed to set user option: ") + fido_strerr(r));
	}
	r = fido_dev_make_cred(dev.get(), cred_ptr,"XXXX");
	if (r != FIDO_OK) {
		throw std::runtime_error(std::string("Failed to register credential: ") + fido_strerr(r));
	}
	StoredCredential stored(credential.get());
	return stored;
}

static const std::string DEFAULT_CRED_FILE = "./cred.fido2";

static void do_register_credential(std::shared_ptr<fido_dev_t> dev) {
	try {
		std::cout << "File in which to save the credential? [" << DEFAULT_CRED_FILE << "] ";
		std::string out_file;
		std::getline(std::cin, out_file);
		out_file = trim(out_file);
		if (out_file == "") {
			out_file = DEFAULT_CRED_FILE;
		}
		StoredCredential result = _register_credential(dev);
		std::cout << "Auth data (len " << result.cred_id.size() << "): " << dump_hex(result.cred_id) << "\n";
		std::cout << "Client data hash (len " << result.client_data_hash.size() << "): " << dump_hex(result.client_data_hash) << "\n";
		std::cout << "Cred ID (len " << result.cred_id.size() << "): " << dump_hex(result.cred_id) << "\n";
		std::cout << "Cred pubkey (len " << result.pubkey.size() << "): " << dump_hex(result.pubkey) << "\n";
		std::cout << "Cred signature (len " << result.sig.size() << "): " << dump_hex(result.sig) << "\n";
		KeyStore("simo").add_key(result.getCredential());
		std::cout << "Success!\n";
	} catch (std::runtime_error& e) {
		std::cerr << "Error while registering credential: " << e.what() << "\n";
	}
}

static bool do_auth(std::shared_ptr<fido_dev_t> dev, bool include_allow_list) {
	fido_assert_t* assert = fido_assert_new();
	auto allowed_keys = KeyStore{"simo"}.list_keys();
	/*
	 * Set the following values:
	 * -   type;
	 * -   client data hash;
	 * -   relying party;
	 * -   user attributes;
	 * -   list of excluded credential IDs;
	 * -   resident key and user verification attributes.
	 */
	auto r = fido_assert_set_up(assert, FIDO_OPT_TRUE);
	if (r != FIDO_OK) {
		std::cerr << "Failed to set UP flag: " << fido_strerr(r) << "\n";
		return false;
	}
	r = fido_assert_set_uv(assert, FIDO_OPT_TRUE);
	if (r != FIDO_OK) {
		std::cerr << "Failed to set UV flag: " << fido_strerr(r) << "\n";
		return false;
	}
	r = fido_assert_set_rp(assert, "ttclabs.me");
	if (r != FIDO_OK) {
		std::cerr << "Failed to set client data hash: " << fido_strerr(r) << "\n";
		return false;
	}
	r = fido_assert_set_clientdata_hash(assert, get_clientdata_hash().data(), 32);
	if (r != FIDO_OK) {
		std::cerr << "Failed to set client data hash: " << fido_strerr(r) << "\n";
		return false;
	}
	if (include_allow_list) {
		for (const auto& cred : allowed_keys) {
			r = fido_assert_allow_cred(assert, (const unsigned char*)cred.cred_id.data(), cred.cred_id.size());
			if (r != FIDO_OK) {
				std::cerr << "Failed to include credential: " << fido_strerr(r) << "\n";
				return false;
			}
		}
	}
	r = fido_dev_get_assert(dev.get(), assert, "XXXX");
	if (r != FIDO_OK) {
		std::cerr << "Failed to authenticate credential: " << fido_strerr(r) << "\n";
		return false;
	}
	//auto assertions = Assertion::Assertion::parseGetAssertionResponse(assert);
	//for (const auto& a : assertions) {
	for (int i = 0; i < fido_assert_count(assert); ++i) {
		//auto cred_data = a.cred_data;
		//if (!cred_data) {
		//continue;
		//}
		//std::cout << "Key provided credential: " << Hex::encode(cred_data->cred_id) << "\n";
		for (auto& k : allowed_keys) {
			std::cout << "Attempting key" << Hex::encode(k.pubkey) << "\n";
			auto verify_result = fido_assert_verify(assert, i, COSE_ES256 /* TODO */, k.pubkey.data()/*to_libfido2_key().get()*/);
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

static void do_auth_allow(std::shared_ptr<fido_dev_t> dev) {
	(void)do_auth(dev, true);
}

static void do_auth_credential(std::shared_ptr<fido_dev_t> dev) {
	(void)do_auth(dev, false);
}

static std::shared_ptr<fido_dev_t> open_dev(const fido_dev_info_t* dev) {
	std::shared_ptr<fido_dev_t> result(fido_dev_new(), [](fido_dev_t* dev) {fido_dev_free(&dev);});
	if (!result) {
		return nullptr;
	}

	if (fido_dev_open(result.get(), fido_dev_info_path(dev)) != FIDO_OK) {
		std::cerr << "Couldn't open " << fido_dev_info_path(dev) << "\n";
		return nullptr;
	}
	return result;
}

static void do_exit(std::shared_ptr<fido_dev_t> dev) {
	(void)dev;
	std::cout << "Bye!\n";
	::exit(0);
}

int main(void) {
	size_t ndevs;
	int r;

	fido_init(0);

	auto devlist = fido_dev_info_new(64);

	if (!devlist) {
		std::cerr << "fido_dev_info_new failed.";
		return 1;
	}

	if ((r = fido_dev_info_manifest(devlist, 64, &ndevs)) != FIDO_OK) {
		std::cerr << "fido_dev_info_manifest: " << fido_strerr(r) << "(" << r << ")" << "\n";
		return 2;
	}

	const fido_dev_info_t* selected_dev = nullptr;
	if (ndevs == 0) {
		std::cerr << "No valid FIDO2 devices found.\n";
		return -1;
	} else if (ndevs > 1) {
		while (!selected_dev) {
			/* More than 1 device found. Present a menu to decide which device to use. */
			std::cout << "Select the device to use [0-" << ndevs - 1 << "] or (q)uit:\n";
			for (size_t i = 0; i < ndevs; i++) {
				const fido_dev_info_t *di = fido_dev_info_ptr(devlist, i);
				std::cout << "\t " << i << ") " << dev_info_str(di) << "\n";
			}
			std::string str;
			std::getline(std::cin, str);
			if (::tolower(str[0]) == 'q') {
				std::cout << "Nevermind.\n";
				return 0;
			}
			std::istringstream in(str);
			size_t sel;
			in >> sel;
			if (!in.fail() && sel >= 0 && sel < ndevs) {
				selected_dev = fido_dev_info_ptr(devlist, sel);
			} else {
				std::cout << "Invalid selection.\n";
			}
		}
	} else {
		selected_dev = fido_dev_info_ptr(devlist, 0);
	}
	std::cout << "Using device: [" << dev_info_str(selected_dev) << "]\n";

	auto dev_handle = open_dev(selected_dev);
	if (!dev_handle) {
		return 1;
	}

	struct CallbackData {
		std::string description;
		decltype(&do_register_credential) cb;
	};
	std::array<CallbackData, 4> callbacks{
		"Quit", &do_exit,
		"Register new credential", &do_register_credential,
		"Authenticate", &do_auth_credential,
		"Verify keys (aka U2F)", &do_auth_allow
	};

	while (1) {
		std::cout << "Please select a choice [1-" << callbacks.size() << "]:\n";
		for (size_t i = 0; i < callbacks.size(); ++i) {
			std::cout << "    " << i << ") " << callbacks[i].description << "\n";
			std::string str;
		}
		int sel = -1;
		while (sel < 0) {
			std::string str;
			std::getline(std::cin, str);
			std::istringstream in(str);
			in >> sel;
			if (in.fail() || sel <= 0 || (size_t)sel > callbacks.size()) {
				std::cout << "Invalid selection.\n";
				sel = -1;
			}
		}
		callbacks[sel].cb(dev_handle);
	}
	fido_dev_info_free(&devlist, ndevs);

	return 0;
}
