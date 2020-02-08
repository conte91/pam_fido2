#ifndef __ASSERTION_H
#define __ASSERTION_H

#include <array>
#include <memory>
#include <string>
#include <vector>

#include <fido.h>

#include "Credential.h"

namespace Assertion {

class AttestedCredData {
	AttestedCredData(const std::string& data);
	AttestedCredData() = default;
	public:
		Credential get_credential();
		std::string get_raw_auth_data();
	private:
		Credential _cred;
		std::string _raw_auth_data;
};

#if 0
struct AuthData {
	std::array<uint8_t, 32> rp_id_hash;
	bool user_present;
	bool user_verified;
	uint32_t sign_count;
	std::shared_ptr<AttestedCredData> cred_data;
	AuthData(const std::string& data);
	AuthData() = default;
};
#endif

struct Assertion {
	std::shared_ptr<std::string> display_name;
	std::shared_ptr<std::string> user_name;
	std::shared_ptr<AttestedCredData> cred_data;

	Assertion() = default;
	static std::vector<Assertion> parseGetAssertionResponse(const fido_assert_t* assert);
	bool verify(const Credential& cred);

private:
	Assertion(const fido_assert_t* cred, size_t idx);
};

class AssertionRequest {
};

} // namespace Assertion

#endif // __ASSERTION_H
