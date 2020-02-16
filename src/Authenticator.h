#ifndef __AUTHENTICATOR_H
#define __AUTHENTICATOR_H

#include <functional>
#include <memory>
#include <vector>

#include "HostId.h"
#include "KeyStore.h"
#include "StoredCredential.h"
#include "UserId.h"

class Authenticator {
	public:
	typedef std::unique_ptr<fido_assert_t, void(*)(fido_assert_t*)> Assertion;
	Authenticator(const fido_dev_info_t* dev);

	Assertion get_assertion();
	Assertion get_assertion(const std::vector<Credential>& allow_list);

	bool verify_assertion(const Assertion& assertion, const std::vector<Credential>& allowed_keys);

	bool authenticate(const KeyStore& keystore, bool include_allow_list);

	/**
	 * Registers a new credential on the device.
	 *
	 * @param resident If true, store the key on the authenticator
	 *                 for passwordless (FIDO2) authentication.
	 */
	StoredCredential make_credential(const HostId& host, const UserId& user, bool resident_key);

	static std::vector<std::shared_ptr<fido_dev_t>> list_devs();

	/**
	 * Sets a function to be used to request a PIN from the user.
	 */
	void set_pin_callback(std::function<std::string(void*)> cb, void* cb_param);

	private:
	std::unique_ptr<fido_dev_t, void(*)(fido_dev_t*)> _dev;
	Assertion run_get_assert_request(const std::vector<Credential>& allowed_keys, bool include_allow_list);

	std::string _pin;
	std::function<std::string(void*)> _pin_cb;
	void* _pin_cb_param;
	bool _require_pin;
};

#endif // __AUTHENTICATOR_H
