#include "KeyStore.h"

#include <cerrno>
#include <cstring>
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>

#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "Credential.h"
#include "hex.h"
#include "util.h"

KeyStore::KeyStore(const UserId& user_data) :
	_user_data(user_data) {
}

std::vector<Credential> KeyStore::list_keys() const {
	ChangeEUID euid_change{_user_data.user_id};
	std::ifstream file(get_user_keys_file());
	if (!file.good()) {
		throw std::runtime_error("Failed to open " + get_user_keys_file() + " for reading.\n");
	}

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
		//std::cout << "Reading " << line << "\n";
		parse >> user >> cred_id >> key;
		//std::cout << "User: " << user << ", credential ID: " << cred_id << ", key: " << key << "\n";
		if (parse.fail()) {
			//std::cout << "Invalid credential file.\n";
			return {};
		}
		if (user != _user_data.username) {
			continue;
		}
		std::string decoded_key = Hex::decode(key);
		std::string decoded_cred_id = Hex::decode(cred_id);
		if (decoded_key == "" || decoded_cred_id == "") {
			//std::cout << "Invalid credential file.\n";
			return {};
		}
		result.push_back(Credential{decoded_cred_id, decoded_key});
	}
	return result;
}

void KeyStore::add_key(const Credential& cred) {
	create_keystore_directory();
	auto key_filename = get_user_keys_file();
	std::ofstream file{key_filename, std::ofstream::app};
	if (!file.good()) {
		throw std::runtime_error("Failed to open " + get_user_keys_file() + " for writing.\n");
	}
	file << "\n";
	std::string encoded_key = Hex::encode(cred.pubkey);
	std::string encoded_id = Hex::encode(cred.cred_id);
	//std::cout << "Appending credential " << encoded_id << "(key: " << encoded_key << ") for user " << _user_data.username << "\n";
	file << _user_data.username << " " << encoded_id << " " << encoded_key << "\n";
}

void KeyStore::create_keystore_directory() const {
	auto config_dir = get_user_config_path();
	DIR* dir = opendir(config_dir.c_str());
	if (dir) {
		closedir(dir);
		return;
	}
	if (errno != ENOENT) {
		/* Couldn't open the directory for some reason. */
		std::ostringstream err;
		err << "Failed to open directory " << config_dir;
		err << ": " << strerror(errno) << ".";
		throw std::runtime_error(err.str());
	}
	/* Directory does not exist. */
	if(mkdir(config_dir.c_str(), 0700)) {
		std::ostringstream err;
		err << "Failed to create directory " << config_dir;
		err << ": " << strerror(errno) << ".";
		throw std::runtime_error(err.str());
	}
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

