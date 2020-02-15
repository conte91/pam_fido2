#include "UserId.h"

#include <cerrno>
#include <cstring>
#include <iostream>
#include <sstream>

#include <sys/types.h>
#include <pwd.h>

void UserId::init(const struct passwd* user_data) {
	if (!user_data) {
		std::ostringstream err;
		err << "Failed to fetch user information: ";
		err << strerror(errno) << ".";
		throw std::runtime_error(err.str());
	}
	this->username = std::string(user_data->pw_name);
	//std::cout << "Username: " << this->username << "\n";
	if (user_data->pw_gecos && strlen(user_data->pw_gecos) > 0) {
		this->display_name = std::string(user_data->pw_gecos);
	} else {
		this->display_name = this->username;
	}
	//std::cout << "Display name: " << this->display_name << "\n";
	this->user_id = user_data->pw_uid;
	//std::cout << "User ID:" << this->user_id << "\n";
	this->home_dir = std::string(user_data->pw_dir);
	//std::cout << "Home dir:" << this->home_dir << "\n";
}

UserId::UserId(const std::string& username) {
	init(getpwnam(username.c_str()));
}

UserId::UserId(uid_t uid) {
	init(getpwuid(uid));
}

UserId::UserId(const struct passwd* user_data) {
	init(user_data);
}
