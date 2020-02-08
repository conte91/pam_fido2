#include "KeyStore.h"

#include <iomanip>
#include <iostream>
#include <sstream>

#include "hex.h"

void show_keys(const KeyStore& ks) {
	for (const auto& k : ks.list_keys()) {
		std::cout << "Credential ID: " << Hex::encode(k.cred_id);
		std::cout << ", key: " << Hex::encode(k.pubkey);
		std::cout << "\n";
	}
}

int main(int argc, char** argv) {
	KeyStore ks{"simo"};
	while (1) {
		show_keys(ks);
		std::cout << "Add key, or (q): ";
		std::string key;
		std::cin >> key;
		if (key == "q") {
			break;
		}
		std::cout << "Add pubkey, or (q): ";
		std::string pubkey;
		std::cin >> pubkey;
		if (pubkey == "q") {
			break;
		}
		ks.add_key({Hex::decode(key), Hex::decode(pubkey)});
	}
	return 0;
}

