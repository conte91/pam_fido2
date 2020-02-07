#include "KeyStore.h"

#include <fstream>
#include <iostream>
#include <sstream>
#include <string>

#include "hex.h"
#include "util.h"

std::string get_config_dir() {
	/* TODO */
	return "/home/simo/.config/fido2";
}

KeyStore::KeyStore(const std::string& username) :
	_username(username) {
}

std::vector<std::string> extract_keys_from_file(const std::string& username, const std::string& filename) {
	std::ifstream file(filename);

	auto result = std::vector<std::string>{};

	while (file.good()) {
		std::string line;
		std::getline(file, line);
		line = trim(line);
		if (line[0] == '#' || line == "") {
			continue;
		}
		
		std::string user;
		std::string key;
		std::istringstream parse(line);
		std::cout << "Reading " << line << "\n";
		parse >> user >> key;
		std::cout << "User: " << user << ", key: " << key << "\n";
		if (parse.fail()) {
			return {};
		}
		if (user != username) {
			continue;
		}
		std::string decoded_key = Hex::decode(key);
		if (decoded_key == "") {
			return {};
		}
		result.push_back(decoded_key);
	}
	return result;
}

std::vector<std::string> KeyStore::list_keys() const {
	/* TODO
	std::string config_dir = get_config_dir();
	return get_config_dir()
	*/
	return extract_keys_from_file("simo", "/home/simo/.config/fido2/keys");
}

void KeyStore::add_key(const std::string& key) {
	auto filename = "/home/simo/.config/fido2/keys";
	std::ofstream file{filename, std::ofstream::app};
	file << "\n";
	std::string encoded = Hex::encode(key);
	std::cout << "Appending " << encoded << " for user " << _username << "\n";
	file << _username << " " << encoded << "\n";
}
