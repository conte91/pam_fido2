#include "hex.h"

#include <iomanip>
#include <iostream>
#include <sstream>

#include <cryptopp/hex.h>

std::string Hex::decode(const std::string& input) {
	std::string decoded;
	if (input.size() % 2 != 0) {
		return "";
	}
	decoded.resize(input.size() / 2);
	for (size_t i = 0; i < input.size() / 2; ++i) {
		unsigned char c;
		std::string slice = input.substr(i * 2, 2);
		try {
			c = std::stoi(slice, 0, 16);
		} catch (const std::invalid_argument&) {
			return "";
		} catch (const std::out_of_range&) {
			return "";
		}
		decoded[i] = c;
	}
	return decoded;
}

std::string Hex::encode(const std::string& input) {
	std::ostringstream encoded;
	for (auto& c : input) {
		encoded << std::setw(2) << std::setfill('0') << std::hex <<
			std::uppercase << (unsigned int)(unsigned char)c;
	}
	return encoded.str();
}
