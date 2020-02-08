#include "KeyStore.h"

#include <fstream>
#include <iostream>
#include <sstream>
#include <string>

#include "Credential.h"
#include "hex.h"
#include "util.h"

std::string get_config_dir() {
	/* TODO */
	return "/home/simo/.config/fido2";
}

KeyStore::KeyStore(const std::string& username) :
	_username(username) {
}

std::vector<Credential> extract_keys_from_file(const std::string& username, const std::string& filename) {
	std::ifstream file(filename);

	auto result = std::vector<Credential>{};

	while (file.good()) {
		std::string line;
		std::getline(file, line);
		line = trim(line);
		if (line[0] == '#' || line == "") {
			continue;
		}
		
		std::string user;
		std::string cred_id;
		std::string key;
		std::istringstream parse(line);
		std::cout << "Reading " << line << "\n";
		parse >> user >> cred_id >> key;
		std::cout << "User: " << user << ", credential ID: " << cred_id << ", key: " << key << "\n";
		if (parse.fail()) {
			std::cout << "Invalid credential file.\n";
			return {};
		}
		if (user != username) {
			continue;
		}
		std::string decoded_key = Hex::decode(key);
		std::string decoded_cred_id = Hex::decode(cred_id);
		if (decoded_key == "" || decoded_cred_id == "") {
			std::cout << "Invalid credential file.\n";
			return {};
		}
		result.push_back(Credential{decoded_cred_id, decoded_key});
	}
	return result;
}

std::vector<Credential> KeyStore::list_keys() const {
	/* TODO
	std::string config_dir = get_config_dir();
	return get_config_dir()
	*/
	return extract_keys_from_file("simo", "/home/simo/.config/fido2/keys");
}

void KeyStore::add_key(const Credential& cred) {
	auto filename = "/home/simo/.config/fido2/keys";
	std::ofstream file{filename, std::ofstream::app};
	file << "\n";
	std::string encoded_key = Hex::encode(cred.pubkey);
	std::string encoded_id = Hex::encode(cred.cred_id);
	std::cout << "Appending credential " << encoded_id << "(key: " << encoded_key << ") for user " << _username << "\n";
	file << _username << " " << encoded_id << " " << encoded_key << "\n";
}
