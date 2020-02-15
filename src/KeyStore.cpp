#include "KeyStore.h"

#include <fstream>
#include <iostream>
#include <sstream>
#include <string>

#include "Credential.h"
#include "hex.h"
#include "util.h"

KeyStore::KeyStore(const UserId& user_data) :
	_user_data(user_data) {
}

std::vector<Credential> KeyStore::list_keys() const {
	ChangeEUID euid_change{_user_data.user_id};
	std::ifstream file(get_user_keys_file());

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
		if (user != _user_data.username) {
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

void KeyStore::add_key(const Credential& cred) {
	std::ofstream file{get_user_keys_file(), std::ofstream::app};
	file << "\n";
	std::string encoded_key = Hex::encode(cred.pubkey);
	std::string encoded_id = Hex::encode(cred.cred_id);
	std::cout << "Appending credential " << encoded_id << "(key: " << encoded_key << ") for user " << _user_data.username << "\n";
	file << _user_data.username << " " << encoded_id << " " << encoded_key << "\n";
}

std::string KeyStore::get_user_config_path() const {
	std::ostringstream ss;
	ss << _user_data.home_dir << "/.config";
	ss << "/fido2";
	return ss.str();
}

std::string KeyStore::get_user_keys_file() const {
	return get_user_config_path() + "/keys";
}
