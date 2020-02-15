#include "util.h"

#include <cstring>
#include <sstream>
#include <vector>

#include <unistd.h>

std::string ltrim(const std::string& str, const std::string& chars) {
	std::string result{str};
    result.erase(0, result.find_first_not_of(chars));
    return result;
}

std::string rtrim(const std::string& str, const std::string& chars) {
	std::string result{str};
    result.erase(result.find_last_not_of(chars) + 1);
    return result;
}

std::string trim(const std::string& str, const std::string& chars) {
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
