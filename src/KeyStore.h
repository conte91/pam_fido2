#ifndef __KEY_STORE_H
#define __KEY_STORE_H

#include <string>
#include <vector>

#include "Credential.h"

class KeyStore {
	public:
	KeyStore(const std::string& username);
	std::vector<Credential> list_keys() const;
	void add_key(const Credential& cred);

	private:
	std::string _username;
	
};

#endif // __KEY_STORE_H
