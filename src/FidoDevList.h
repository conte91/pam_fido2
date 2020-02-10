#ifndef __FIDO_DEV_LIST_H
#define __FIDO_DEV_LIST_H

#include <cstdlib>

#include <fido.h>

class FidoDevList {
	public:
	FidoDevList();
	~FidoDevList();

	size_t size() const;
	const fido_dev_info_t* get(size_t idx) const;

	private:
	fido_dev_info_t* _dev_info;
	size_t _n_devs;
	static constexpr int max_devs = 128;
};

#endif // __FIDO_DEV_LIST_H
