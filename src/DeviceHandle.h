#ifndef __DEVICE_HANDLE_H
#define __DEVICE_HANDLE_H

#include <fido.h>

/**
 * FIDO Device handle.
 *
 * Wrapper around fido_dev_t*, with
 * automatic resource management.
 */
class DeviceHandle {
	public:
	DeviceHandle(const fido_dev_info_t* dev);
	~DeviceHandle();
	fido_dev_t* get() const;

	private:
	fido_dev_t* _dev;
};

#endif // __DEVICE_HANDLE_H
