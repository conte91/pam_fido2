#include "Config.h"

#include <fstream>
#include <iostream>
#include <sstream>
#include <string>

#include <sys/utsname.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include "util.h"
/**
 * Gets the FQDN of the current machine.
 */
static std::string _get_fqdn() {
	struct utsname uts_name;
	int uname_result = uname(&uts_name);
	if (uname_result) {
		std::ostringstream err;
		err << "Failed to run uname(): " << errno << ".";
		throw std::runtime_error(err.str());
	}

	struct addrinfo hints = {0}, *info;
	int gai_result;
	hints.ai_family = AF_UNSPEC;
	hints.ai_flags = AI_CANONNAME;

	if ((gai_result = getaddrinfo(uts_name.nodename, NULL, &hints, &info)) != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(gai_result));
		exit(1);
	}

	if (!info) {
		return std::string(uts_name.nodename);
	}
	for (struct addrinfo *p = info; p; p = p->ai_next) {
		if (p->ai_canonname && p->ai_canonname[0]) {
			std::cout << "Hostname " << p->ai_canonname << "\n";
		}
	}

	std::string result{info->ai_canonname};
	freeaddrinfo(info);
	return result;
}

std::string Config::get_config_path() {
	return "/etc/fido2";
}

std::string Config::get_config_file() {
	return get_config_path() + "/config";
}

HostId Config::get_host_id() const {
	return HostId{hostname, display_name};
}

Config Config::read_from_file() {
	std::ifstream in_file(get_config_file());
	Config result = default_config();
	if (!in_file.good()) {
		return result;
	}
	size_t lineno = 1;
	while (1) {
		std::string s;
		std::getline(in_file, s);
		if (!in_file.good()) {
			break;
		}
		if (trim(s) == "" || s[0] == '#') {
			continue;
		}
		auto equal_pos = s.find_first_of('=');
		if (equal_pos == std::string::npos || equal_pos == 0) {
			throw ConfigurationParseError(lineno, "Line must be in the format <item>=<value>.");
		}
		auto item = trim(s.substr(0, equal_pos));
		auto val = trim(s.substr(equal_pos + 1));
		std::cout << "Item " << item << "Val " << val << "\n";
		if (item == "hostname") {
			if (val == "") {
				throw ConfigurationParseError(lineno, "Hostname can't be empty.");
			}
			result.hostname = val;
		} else if (item == "display_name") {
			result.display_name = val;
		}
	}
	return result;
}

Config Config::default_config() {
	Config result{};
	result.hostname = _get_fqdn();
	result.display_name = {};
	return result;
}

static std::string get_config_file_error(size_t lineno, const std::string& reason) {
	std::ostringstream err;
	err << "Invalid configuration found. At line " << lineno << ": " << reason;
	return err.str();
}

ConfigurationParseError::ConfigurationParseError(size_t lineno, const std::string& reason) :
	std::runtime_error(get_config_file_error(lineno, reason)) {
}
