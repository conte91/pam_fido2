#include "DeviceHandle.h"

#include <stdexcept>

DeviceHandle::DeviceHandle(const fido_dev_info_t* dev_info) {
	_dev = fido_dev_new();
	if (!_dev) {
		throw std::runtime_error("fido_dev_new() failed.\n");
	}

	auto dev_path = fido_dev_info_path(dev_info);
	if (!dev_path) {
		throw std::runtime_error("Null dev_path returned by fido_dev_info_path.");
	}
	if (fido_dev_open(_dev, dev_path) != FIDO_OK) {
		throw std::runtime_error(std::string("Couldn't open ") + dev_path + "\n");
	}
}

DeviceHandle::~DeviceHandle() {
	if (_dev) {
		/* If the device is already closed, this is a NOP. */
		fido_dev_close(_dev);
		fido_dev_free(&_dev);
	}
}

fido_dev_t* DeviceHandle::get() const {
	return _dev;
}
