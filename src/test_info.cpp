#include <iomanip>
#include <iostream>
#include <sstream>

#include <fido.h>

std::string dev_info_str(const fido_dev_info_t* di) {
	std::ostringstream result;
	result << fido_dev_info_path(di) << ": vendor=0x" <<
		std::hex << std::setfill('0') << std::setw(4) <<
		(uint16_t)fido_dev_info_vendor(di) <<
		(uint16_t)fido_dev_info_product(di) <<
		" (" << fido_dev_info_manufacturer_string(di) <<
		" " << fido_dev_info_product_string(di) << ")";
	return result.str();
}

int main(void) {
	fido_dev_info_t *devlist;
	size_t ndevs;
	int r;

	fido_init(0);

	if ((devlist = fido_dev_info_new(64)) == NULL) {
		std::cerr << "fido_dev_info_new failed.";
		return 1;
	}

	if ((r = fido_dev_info_manifest(devlist, 64, &ndevs)) != FIDO_OK) {
		std::cerr << "fido_dev_info_manifest: " << fido_strerr(r) << "(" << r << ")" << "\n";
		return 2;
	}

	const fido_dev_info_t* selected_dev;
	if (ndevs != 1) {
		for (size_t i = 0; i < ndevs; i++) {
			const fido_dev_info_t *di = fido_dev_info_ptr(devlist, i);
		}
	} else {
		selected_dev = fido_dev_info_ptr(devlist, 0);
	}
	std::cout << "Using device: [" << dev_info_str(selected_dev) << "]\n";

	fido_dev_info_free(&devlist, ndevs);

	return 0;
}
