#ifndef __AUTHENTICATOR_H
#define __AUTHENTICATOR_H

#include <functional>
#include <memory>
#include <vector>

#include "DeviceHandle.h"
#include "HostId.h"
#include "KeyStore.h"
#include "StoredCredential.h"
#include "UserId.h"

class Authenticator {
	public:
	typedef std::unique_ptr<fido_assert_t, void(*)(fido_assert_t*)> Assertion;
	/**
	 * Initializes authenticator data, pointing to the given device..
	 * The actual device will be open and closed as needed.
	 *
	 * @param[in] dev_info Pointer to the device metadata. This must remain valid
	 *                     for the whole lifetime of the Authenticator.
	 * @param[in] host Information on the host that the device is authenticating on.
	 */
	Authenticator(const fido_dev_info_t* dev_info, const HostId& host);

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
	StoredCredential make_credential(const UserId& user, bool resident_key);

	static std::vector<std::shared_ptr<fido_dev_t>> list_devs();

	/**
	 * Sets a function to be used to request a PIN from the user.
	 */
	void set_pin_callback(std::function<std::string(void*)> cb, void* cb_param);

	private:
	Assertion run_get_assert_request(const std::vector<Credential>& allowed_keys, bool include_allow_list);

	const fido_dev_info_t* _dev_info;
	std::string _pin;
	std::function<std::string(void*)> _pin_cb;
	void* _pin_cb_param;
	bool _require_pin;

	HostId _host;
};

#endif // __AUTHENTICATOR_H
