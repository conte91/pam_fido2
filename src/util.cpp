#include "util.h"

#include <cstring>
#include <sstream>
#include <vector>

#include <unistd.h>

std::string& ltrim(std::string& str, const std::string& chars) {
    str.erase(0, str.find_first_not_of(chars));
    return str;
}

std::string& rtrim(std::string& str, const std::string& chars) {
    str.erase(str.find_last_not_of(chars) + 1);
    return str;
}

std::string& trim(std::string& str, const std::string& chars) {
    return ltrim(rtrim(str, chars), chars);
}

static void _set_euid(int euid) {
	if (seteuid(euid)) {
		std::ostringstream err;
		err << "Failed to change EUID to " << euid;
		err << ": " << strerror(errno) << ".";
		throw std::runtime_error(err.str());
	}
}

ChangeEUID::ChangeEUID(uid_t euid) :
	_old_euid(geteuid()) {
	_set_euid(euid);
}

ChangeEUID::~ChangeEUID() {
	_set_euid(_old_euid);
}
