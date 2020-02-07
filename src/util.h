#ifndef __UTIL_H
#define __UTIL_H

#include <string>
std::string& ltrim(std::string& str, const std::string& chars = "\t\n\v\f\r ");

std::string& rtrim(std::string& str, const std::string& chars = "\t\n\v\f\r ");

std::string& trim(std::string& str, const std::string& chars = "\t\n\v\f\r ");

#endif // __UTIL_H
