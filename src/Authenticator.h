#ifndef __AUTHENTICATOR_H
#define __AUTHENTICATOR_H

#include <memory>
#include <vector>

#include "HostId.h"
#include "KeyStore.h"
#include "StoredCredential.h"
#include "UserId.h"

class Authenticator {
	private:
	std::unique_ptr<fido_dev_t, void(*)(fido_dev_t*)> _dev;
	
	public:
	Authenticator(std::shared_ptr<fido_dev_info_t> dev_info);
	bool authenticate(const KeyStore& keystore, bool include_allow_list);
	/**
	 * Registers a new credential on the device.
	 *
	 * @param resident If true, store the key on the authenticator
	 *                 for passwordless (FIDO2) authentication.
	 */
	StoredCredential make_credential(const HostId& host, const UserId& user, bool resident_key);

	static std::vector<std::shared_ptr<fido_dev_t>> list_devs();
};

#endif // __AUTHENTICATOR_H
