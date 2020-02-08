#include "Credential.h"

extern "C" {
#include <fido.h>
#include <fido/es256.h>
}
#include <memory>

std::shared_ptr<const es256_pk_t> Credential::to_libfido2_key() const {
	std::shared_ptr<es256_pk_t> result(
		es256_pk_new(),
		[](es256_pk_t* data) { es256_pk_free(&data); }
		);
	auto conversion_result = es256_pk_from_ptr(result.get(), pubkey.data(), pubkey.size());
	if (conversion_result != FIDO_OK) {
		throw std::runtime_error("Failed to convert key to ES256.");
	}
	return result;
}
