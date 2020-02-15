#ifndef __KEY_STORE_H
#define __KEY_STORE_H

#include <string>
#include <vector>

#include "Credential.h"
#include "UserId.h"

class KeyStore {
	public:
	KeyStore(const UserId& user_data);
	std::vector<Credential> list_keys() const;
	void add_key(const Credential& cred);

	static std::string get_config_path();
	static std::string get_config();

	private:
	UserId _user_data;
	std::string get_user_config_path() const;
	std::string get_user_keys_file() const;
};

#endif // __KEY_STORE_H
