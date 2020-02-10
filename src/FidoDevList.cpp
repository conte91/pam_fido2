#include "FidoDevList.h"

#include <cstdlib>
#include <memory>
#include <sstream>

FidoDevList::FidoDevList() {
	_dev_info = fido_dev_info_new(max_devs);
	if (!_dev_info) {
		throw std::runtime_error("fido_dev_info_new failed.\n");
	}
	auto r = fido_dev_info_manifest(_dev_info, max_devs, &_n_devs);
	if (r != FIDO_OK) {
		std::ostringstream err;
		err << "fido_dev_info_manifest: " << fido_strerr(r) << "(" << r << ")";
		throw std::runtime_error(err.str());
	}
}

FidoDevList::~FidoDevList() {
	if (_dev_info) {
		fido_dev_info_free(&_dev_info, max_devs);
	}
}
size_t FidoDevList::size() const {
	return _n_devs;
}

const fido_dev_info_t* FidoDevList::get(size_t idx) const {
	return fido_dev_info_ptr(_dev_info, idx);
}
