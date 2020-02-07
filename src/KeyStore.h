#ifndef __KEY_STORE_H
#define __KEY_STORE_H

#include <string>
#include <vector>

class KeyStore {
	public:
	KeyStore(const std::string& username);
	std::vector<std::string> list_keys() const;
	void add_key(const std::string& key);

	private:
	std::string _username;
	
};

#endif // __KEY_STORE_H
