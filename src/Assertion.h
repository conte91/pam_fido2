#ifndef __ASSERTION_H
#define __ASSERTION_H

#include <array>
#include <memory>
#include <string>
#include <vector>

#include <fido.h>

namespace Assertion {

struct AttestedCredData {
	std::array<uint8_t, 16> aaguid;
	std::string cred_id;
	std::string pubkey;
	AttestedCredData(const std::string& data);
	AttestedCredData() = default;
};

struct AuthData {
	std::array<uint8_t, 32> rp_id_hash;
	bool user_present;
	bool user_verified;
	uint32_t sign_count;
	std::shared_ptr<AttestedCredData> cred_data;
	AuthData(const std::string& data);
	AuthData() = default;
};

struct Assertion {
	std::shared_ptr<std::string> display_name;
	std::shared_ptr<std::string> user_name;
	AuthData auth_data;

	Assertion() = default;
	static std::vector<Assertion> parseGetAssertionResponse(const fido_assert_t* assert);
private:
	Assertion(const fido_assert_t* cred, size_t idx);
};

} // namespace Assertion

#endif // __ASSERTION_H
