#ifndef __HEX_H
#define __HEX_H

#include <string>

namespace Hex {
	/**
	 * Decodes the given hex data into binary.
	 *
	 * @param input String to decode.
	 * @return Binary string, or empty string on failure.
	 */
	std::string decode(const std::string& input);
	/**
	 * Encodes the given binary data into hex.
	 *
	 * @param input Binary data to decode.
	 * @return Hex-encoded string representing the input.
	 */
	std::string encode(const std::string& input);
}

#endif // __HEX_H
