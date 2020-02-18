/*
 * Copyright (c) 2003-2007 Andrea Luzzardi <scox@sig11.org>
 *
 * This file is part of the pam_usb project. pam_usb is free software;
 * you can redistribute it and/or modify it under the terms of the GNU General
 * Public License version 2, as published by the Free Software Foundation.
 *
 * pam_usb is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place, Suite 330, Boston, MA  02111-1307  USA
 */

#define PAM_SM_AUTH
#include <security/pam_modules.h>
#include <security/_pam_macros.h>
#include <unistd.h>

#include <string>
#include <sstream>
#include <set>
#include <utility>

#include <sys/types.h>
#include <pwd.h>

#include "Authenticator.h"
#include "Config.h"
#include "FidoDevList.h"
#include "util.h"

//#include "version.h"
//#include "conf.h"
//#include "log.h"
//#include "local.h"
//#include "device.h"

static int _converse(pam_handle_t *pamh, int nargs,
                     const struct pam_message **message,
                     struct pam_response **response) {
  struct pam_conv *conv;
  int retval;

  retval = pam_get_item(pamh, PAM_CONV, (const void **)&conv);

  if (retval != PAM_SUCCESS) {
    return retval;
  }

  return conv->conv(nargs, message, response, conv->appdata_ptr);
}

static char *converse(pam_handle_t *pamh, int echocode, const char *prompt) {
  const struct pam_message msg = {.msg_style = echocode,
                                  .msg = (char *) prompt};
  const struct pam_message *msgs = &msg;
  struct pam_response *resp = NULL;
  int retval = _converse(pamh, 1, &msgs, &resp);
  char *ret = NULL;

  if (retval != PAM_SUCCESS || resp == NULL || resp->resp == NULL ||
      *resp->resp == '\000') {
    if (retval == PAM_SUCCESS && resp && resp->resp) {
      ret = resp->resp;
    }
  } else {
    ret = resp->resp;
  }

  // Deallocate temporary storage.
  if (resp) {
    if (!ret) {
      free(resp->resp);
    }
    free(resp);
  }

  return ret;
}

static void debug_print(pam_handle_t *pamh, int echocode, const char *prompt) {
	free(converse(pamh, PAM_TEXT_INFO, prompt));
}

/**
 * @return List of allowed users.
 */
static std::vector<std::string> do_authentication(pam_handle_t* pamh, const char* pam_user) {
	std::set<std::string> result{};
	
	FidoDevList devs;
	if (devs.size() != 1) {
		debug_print(pamh, PAM_TEXT_INFO, "No devices found.");
		return {};
	}
	Config cfg = Config::read_from_file();
	Authenticator dev_handle{devs.get(0), cfg.get_host_id()};
	auto ask_for_pin = [pamh](void* param) {
		char* pin_resp = converse(pamh, PAM_PROMPT_ECHO_OFF, "Enter PIN: ");
		std::string result{pin_resp};
		free(pin_resp);
		return result;
	};
	dev_handle.set_pin_callback(ask_for_pin, nullptr);

	debug_print(pamh, PAM_TEXT_INFO, "Use your authentication token to login...");
	Authenticator::Assertion assert = dev_handle.get_assertion();
	std::vector<UserId> allowed_users{};
	if (!pam_user || strlen(pam_user) == 0) {
		/* Scan the list of users */
		setpwent();
		struct passwd* user_ent;
		while((user_ent = getpwent())) {
			//debug_print(pamh, PAM_TEXT_INFO, "WOLOLO");
			allowed_users.emplace_back(user_ent);
		}
		endpwent();
	} else {
		allowed_users.emplace_back(std::string(pam_user));
	}

	for (auto& user : allowed_users) {
		//debug_print(pamh, PAM_TEXT_INFO, (std::string("Trying ") +
		//user.username + "...").c_str());
		if (dev_handle.verify_assertion(assert, KeyStore{user}.list_keys())) {
			std::ostringstream msg;
			msg <<  "Authentication successful for user ";
			msg << user.username << " :)";
			//debug_print(pamh, PAM_TEXT_INFO, msg.str().c_str());
			result.insert(user.username);
		}
	}
	if (pam_user && strlen(pam_user)) {
		/* Sanity-check the result if a user was already provided. */
		if (result.size() > 1) {
			throw std::runtime_error("Internal error: too many authentication results.");
		}
		if (result.size() == 1 && *result.begin() != pam_user) {
			throw std::runtime_error("Internal error: Invalid user authenticated.");
		}
	}

	if (result.size() == 0) {
		//debug_print(pamh, PAM_TEXT_INFO, "Authentication failed :(");
	}
	return std::vector<std::string>{result.begin(), result.end()};
}

static std::string _prompt_for_user(pam_handle_t* pamh, const std::vector<std::string>& user_list) {
	std::ostringstream message;
	message << "Available users:\n";
	for (size_t i = 0; i < user_list.size(); ++i) {
		message << "  " << (i + 1) << ") " << user_list[i] << "\n";
	}
	message << "Please select a user:";

	while(1) {
		size_t sel = 0;
		char* resp = converse(pamh, PAM_PROMPT_ECHO_ON, message.str().c_str());
		auto trimmed_resp = trim(std::string{resp});
		free(resp);
		try {
			sel = std::stoi(trimmed_resp);
		} catch(std::invalid_argument&) {
			/* Ignore failed conversions */
		}
		if (sel > 0 && sel <= user_list.size()) {
			return user_list[sel - 1];
		}
		free(converse(pamh, PAM_TEXT_INFO, "Invalid selection."));
	}
}

extern "C" {

static void _free_user_dup(pam_handle_t* pamh, void* data, int error_status) {
	free(data);
}

//PAM_EXTERN
int pam_sm_authenticate(pam_handle_t *pamh, int flags,
		int argc, const char **argv)
{
	try {
		bool set_only = false;
		if (argc == 1 && std::string(argv[0]) == std::string("set_user")) {
			set_only = true;
		} else if (argc != 0) {
			std::ostringstream err;
			err << "Invalid argv [" << argc << "]: ";
			for (int i = 0; i < argc; ++i) {
				err << "'" << argv[i] << "' ";
			}
			debug_print(pamh, PAM_TEXT_INFO, err.str().c_str());
			return PAM_AUTH_ERR;
		}
		if (set_only) {

			const char* pam_user = nullptr;
			int result = pam_get_item(pamh, PAM_USER, (const void**)&pam_user);
			if (result != PAM_SUCCESS) {
				debug_print(pamh, PAM_TEXT_INFO, "Failed to run GET_ITEM");
				return PAM_AUTH_ERR;
			} else if (pam_user && strlen(pam_user) == 0) {
				pam_user = nullptr;
			}

			if (pam_user) {
				debug_print(pamh, PAM_TEXT_INFO, "User already set.");
				return PAM_AUTH_ERR;
			}

			auto auth_result = do_authentication(pamh, "");
			std::string selected_user;
			if (auth_result.size() == 0) {
				debug_print(pamh, PAM_TEXT_INFO, "No valid user found.");
				return PAM_AUTH_ERR;
			}
			if (auth_result.size() == 1) {
				selected_user = *auth_result.begin();
			} else {
				/*
				 * More than one user found.
				 * Prompt the user for his selection.
				 */
				selected_user = _prompt_for_user(pamh, auth_result);
			}

			char* user_dup = strdup(selected_user.c_str());
			if (!user_dup) {
				debug_print(pamh, PAM_TEXT_INFO, "Failed to create string duplicate.");
				return PAM_AUTH_ERR;
			}
			result = pam_set_data(pamh, "fido2", user_dup, _free_user_dup);
			if (result != PAM_SUCCESS) {
				debug_print(pamh, PAM_TEXT_INFO, "Failed to store user info.");
				free(user_dup);
				return PAM_AUTH_ERR;
			}
			result = pam_set_item(pamh, PAM_USER, selected_user.c_str());
			if (result != PAM_SUCCESS) {
				debug_print(pamh, PAM_TEXT_INFO, "Failed to store user info.");
				return PAM_AUTH_ERR;
			}
			return PAM_SUCCESS;
		} else {
			/* Check if the user has already been authenticated by the FIDO2 module. */
			const char* pam_user = nullptr;
			const char* fido2_user = nullptr;

			int result = pam_get_data(pamh, "fido2", (const void**)&fido2_user);
			if (result != PAM_SUCCESS && result != PAM_NO_MODULE_DATA) {
				debug_print(pamh, PAM_TEXT_INFO, "Failed to run GET_DATA");
				return PAM_AUTH_ERR;
			} else if (result == PAM_NO_MODULE_DATA || (fido2_user && strlen(fido2_user) == 0)) {
				fido2_user = nullptr;
			}

			result = pam_get_item(pamh, PAM_USER, (const void**)&pam_user);
			if (result != PAM_SUCCESS) {
				debug_print(pamh, PAM_TEXT_INFO, "Failed to run GET_ITEM");
				return PAM_AUTH_ERR;
			} else if (pam_user && strlen(pam_user) == 0) {
				pam_user = nullptr;
			}

			if (fido2_user && strlen(fido2_user) != 0 &&
				pam_user &&
				strlen(pam_user) != 0 &&
				!strcmp(fido2_user, pam_user)) {
				return PAM_SUCCESS;
			}

			/* No pre-authentication done. */
			auto auth_result = do_authentication(pamh, pam_user);
			std::string selected_user;
			if (auth_result.size() == 0) {
				debug_print(pamh, PAM_TEXT_INFO, "No valid user found.");
				return PAM_AUTH_ERR;
			}
			if (auth_result.size() == 1) {
				selected_user = *auth_result.begin();
			} else {
				/*
				 * More than one user found.
				 * Prompt the user for his selection.
				 */
				selected_user = _prompt_for_user(pamh, auth_result);
			}

			result = pam_set_item(pamh, PAM_USER, selected_user.c_str());
			if (result != PAM_SUCCESS) {
				debug_print(pamh, PAM_TEXT_INFO, "Failed to run SET_ITEM");
				return PAM_AUTH_ERR;
			}
			return PAM_SUCCESS;
		}
	} catch (const std::exception& e) {
		debug_print(pamh, PAM_TEXT_INFO, e.what());
	} catch (...) {
		debug_print(pamh, PAM_TEXT_INFO, "Unknown error occurred.");
	}
	return PAM_AUTH_ERR;
}

PAM_EXTERN
int pam_sm_setcred(pam_handle_t *pamh,int flags,int argc,
		const char **argv)
{
	//debug_print(pamh, PAM_PROMPT_ECHO_ON, "Settingcred");
	return (PAM_SUCCESS);
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
	//debug_print(pamh, PAM_PROMPT_ECHO_ON, "ACCT");
	return PAM_SUCCESS;
}

#ifdef PAM_STATIC

struct pam_module _pam_fido2_modstruct = {
	"pam_fido2",
	pam_sm_authenticate,
	pam_sm_setcred,
	NULL,
	NULL,
	NULL,
	NULL
};

#endif

} // extern "C"
