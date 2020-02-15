#ifndef __USER_ID_H
#define __USER_ID_H

#include <cstdint>
#include <string>

#include <unistd.h>

struct UserId {
	std::string username;
	uid_t user_id;
	std::string display_name;
	std::string home_dir;
	UserId(const std::string& username);
	UserId(uid_t uid);
	UserId(const std::string& username,
		   uint32_t user_id,
		   std::string& display_name);
	private:
	void init(struct passwd* user_data);
};

#endif // __USER_ID_H
