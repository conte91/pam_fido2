#ifndef __UTIL_H
#define __UTIL_H

#include <string>

#include <unistd.h>

/**
 * Left trim a string - thanks C++
 *
 * @param str String to trim
 * @param chars Characters to remove.
 */
std::string& ltrim(std::string& str, const std::string& chars = "\t\n\v\f\r ");

/**
 * Right trim a string - thanks C++
 *
 * @param str String to trim
 * @param chars Characters to remove.
 */
std::string& rtrim(std::string& str, const std::string& chars = "\t\n\v\f\r ");

/**
 * Trim a string - thanks C++
 *
 * @param str String to trim
 * @param chars Characters to remove.
 */
std::string& trim(std::string& str, const std::string& chars = "\t\n\v\f\r ");

class ChangeEUID {
	public:
	/* Changes EUID for the current scope. */
	ChangeEUID(uid_t euid);
	/* Restores the EUID changed by this object. */
	~ChangeEUID();
	private:
	uid_t _old_euid;
};
#endif // __UTIL_H
