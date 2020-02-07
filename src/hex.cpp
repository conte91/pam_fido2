#include "hex.h"

#include <cryptopp/hex.h>

std::string Hex::decode(const std::string& input) {
	std::string decoded;
	CryptoPP::StringSource(input, true,
		new CryptoPP::HexDecoder(
			new CryptoPP::StringSink(decoded)
			)
		);
	return decoded;
}

std::string Hex::encode(const std::string& input) {
	std::string encoded;
	CryptoPP::StringSource(input, true,
		new CryptoPP::HexEncoder(
			new CryptoPP::StringSink(encoded)
			)
		);
	return encoded;
}
