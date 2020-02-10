#ifndef __UTIL_H
#define __UTIL_H

#include <string>

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

#endif // __UTIL_H
