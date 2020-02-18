#include <stdexcept>
#include <string>

#include "HostId.h"

struct Config {

	/** Hostname for this RP (default: queried by gethostname()). */
	std::string hostname;

	/** Display name for this RP (optional, can be "") */
	std::string display_name;

	/** Gets the host bound to this configuration. */
	HostId get_host_id() const;

	/**
	 * Gets the path to the folder containing
	 * configuration data for FIDO2.
	 *
	 * By default, this points to /etc/fido2.
	 */
	static std::string get_config_path();

	/**
	 * Gets the path to the main config file
	 * for FIDO2.
	 *
	 * By default, this points to /etc/fido2/config.
	 */
	static std::string get_config_file();
	static Config read_from_file();
	static Config default_config();
};

class ConfigurationParseError : public std::runtime_error {
	private:
	std::string _what;
	public:
	ConfigurationParseError(size_t lineno, const std::string& reason);
};
