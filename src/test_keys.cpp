#include "KeyStore.h"

#include <iomanip>
#include <iostream>
#include <sstream>

#include "hex.h"

void show_keys(const KeyStore& ks) {
	for (const auto& k : ks.list_keys()) {
		std::cout << "Key: ";
		std::ostringstream ss;
		for (char c : k) {
			ss << std::hex << std::setw(2) << std::setfill('0');
			ss << (int)(unsigned char)c << " ";
		}
		std::cout << ss.str() << "\n";
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
		ks.add_key(Hex::decode(key));
	}
	return 0;
}

