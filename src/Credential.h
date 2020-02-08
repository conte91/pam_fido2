#ifndef __CREDENTIAL_H
#define __CREDENTIAL_H

#include <memory>

extern "C" {
#include <fido.h>
#include <fido/es256.h>
}

struct Credential {
	std::string cred_id;
	std::string pubkey;
	std::shared_ptr<const es256_pk_t> to_libfido2_key() const;
};

#endif // __CREDENTIAL_H
