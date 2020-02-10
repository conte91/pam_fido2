#ifndef __USER_ID_H
#define __USER_ID_H

#include <cstdint>

struct UserId {
	std::string username;
	uint32_t user_id;
	std::string display_name;
};

#endif // __USER_ID_H
