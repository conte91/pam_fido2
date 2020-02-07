#ifndef __HEX_H
#define __HEX_H

#include <string>

namespace Hex {
	std::string decode(const std::string& input);
	std::string encode(const std::string& input);
}

#endif // __HEX_H
