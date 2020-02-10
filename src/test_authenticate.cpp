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
#include "Authenticator.h"
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

static const std::string DEFAULT_CRED_FILE = "./cred.fido2";

static void do_register_credential(Authenticator& dev) {
	try {
		std::cout << "File in which to save the credential? [" << DEFAULT_CRED_FILE << "] ";
		std::string out_file;
		std::getline(std::cin, out_file);
		out_file = trim(out_file);
		if (out_file == "") {
			out_file = DEFAULT_CRED_FILE;
		}
		UserId user = {"simo", 1001, "Simone Baratta"};
		HostId host = {"hans", "Computer di simo."};
		StoredCredential result = dev.make_credential(host, user, false);
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

static void do_auth(Authenticator& dev, bool include_allow_list) {
	if (dev.authenticate(KeyStore{"simo"}, true)) {
		std::cout << "Authentication successful :)\n";
	} else {
		std::cout << "Authentication failed.\n";
	}
}

static void do_auth_allow(Authenticator& dev) {
	do_auth(dev, true);
}

static void do_auth_credential(Authenticator& dev) {
	do_auth(dev, false);
}

static void do_exit(Authenticator& dev) {
	(void)dev;
	std::cout << "Bye!\n";
	::exit(0);
}

int main(void) {
	size_t ndevs;
	int r;

	fido_init(0);

	auto devlist = Authenticator::list_devs();

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

	Authenticator dev_handle{selected_dev};

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
