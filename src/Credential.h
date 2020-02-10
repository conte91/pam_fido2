#ifndef __CREDENTIAL_H
#define __CREDENTIAL_H

#include <memory>

#include <fido.h>
#include <fido/es256.h>

/**
 * Represents a credential known by the authenticator device.
 */
struct Credential {
	/** Credential ID (binary) */
	std::string cred_id;
	/** ES256 key. */
	std::string pubkey;
	/**
	 * Converts this key to a es256_pk_t pointer,
	 * compatible with libfido2 functions.
	 */
	std::shared_ptr<const es256_pk_t> to_libfido2_key() const;
};

#endif // __CREDENTIAL_H
