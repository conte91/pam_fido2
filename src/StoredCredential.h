#ifndef _STORED_CREDENTIAL_H
#define _STORED_CREDENTIAL_H

/**
 * Resident key registered by an authenticator.
 */
struct StoredCredential {
	/**
	 * Hash of the serialized client data,
	 * constructed by the client.
	 */
	std::string client_data_hash;
	/** Raw authenticator data. */
	std::string cred_auth_data;
	/** Registered credential ID. */
	std::string cred_id;
	/** Public key. */
	std::string pubkey;
	/** Signature. */
	std::string sig;

	StoredCredential() = default;
	StoredCredential(const fido_cred_t* cred) {
		auto cdh_ptr = fido_cred_clientdata_hash_ptr(cred);
		auto cdh_len = fido_cred_clientdata_hash_len(cred);
		client_data_hash = std::string(cdh_ptr, cdh_ptr + cdh_len);
		auto cauth_ptr = fido_cred_authdata_ptr(cred);
		auto cauth_len = fido_cred_authdata_len(cred);
		cred_auth_data = std::string(cauth_ptr, cauth_ptr + cauth_len);
		auto cid_ptr = fido_cred_id_ptr(cred);
		auto cid_len = fido_cred_id_len(cred);
		cred_id = std::string(cid_ptr, cid_ptr + cid_len);
		auto pk_ptr = fido_cred_pubkey_ptr(cred);
		auto pk_len = fido_cred_pubkey_len(cred);
		pubkey = std::string(pk_ptr, pk_ptr + pk_len);
		auto sig_ptr = fido_cred_sig_ptr(cred);
		auto sig_len = fido_cred_sig_len(cred);
		sig = std::string(sig_ptr, sig_ptr + sig_len);
	}

	Credential getCredential() const {
		return Credential{cred_id, pubkey};
	}
};

#endif
