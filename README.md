# PAM Fido2 module (pre-alpha)

This PAM module provides secure user- and passwordless logins for Linux systems.

User authentication is performed by sending a FIDO2 assertion request to any compatible FIDO2 device
and verifying the resulting assertions against a set of registered public keys for each user.

_IMPORTANT!_ This software is currently in _EARLY ALPHA_. Consider it something like a really cool thing
to try, and hopefully stick with it of course - but _don't use it in a security-critical environment_ (yet)!

## Installation
The PAM-Fido2 module can be installed as a package, or compiled from source.

### Arch Linux
This package is available [on AUR](https://aur.archlinux.org/packages/pam-fido2)

### Ubuntu
A nightly Ubuntu build is currently WIP. Stay tuned!

### From source
You will need [meson](https://github.com/mesonbuild/meson/pull/6635) and [libcbor](https://github.com/PJK/libcbor) to build the project.

Yubico's `libfido2` is a dependency as well, but is compiled statically into the resulting executables and libraries to maximize compatibility
with different systems.

```
# Clone this repository
git clone https://github.com/Conte91/pam-fido2
cd pam-fido2

# Download the dependencies
git submodule init
git submodule update

# Run meson to configure the build
meson build

# Run ninja to build
ninja -C build

# Install the tools
install -m644 "etc/config" "/etc/fido2/config"
install -m755 "build/fido2_tool" "/usr/bin/fido2_tool"
install -m755 "build/libpam_fido2.so" "/usr/lib/security/pam_fido2.so"
```
## Configuration

### PAM configuration
Add the following to `/etc/pam.d/system-auth`, before the `pam_unix.so` entry.
```
# FIDO2 authentication
auth      sufficient pam_fido2.so
```

This will allow a valid FIDO2 token to be used _instead of_ password (unix) authentication.

### Key registration
The `fido2_tool` program can be used to register new credentials for each user. Just execute the `fido2_tool`,
select a device, and use option `1` to register a new credential for your user. You can try to authenticate
with the newly created credential using option `3`.

## Username-less login

Using the FIDO2 resident key features, PAM-Fido2 can perform authentication without the need to select a user (and yes, it's cool!).

### PAM configuration
In addition to the configuration described in the [Configuration](#configuration) section, you will need to add the following at the top of the PAM
configuration file corresponding to the service you want to login from (e.g. /etc/pam.d/login):

```
auth        optional    pam_fido2.so set_user
```

This will executed `pam_fido2` in "set user" mode: if the authenticator can login multiple users, the host prompts which user one wants to login as.

#### Technical details
Username-less login is composed of two invokations of `pam_fido2.so`: before the username is selected, `pam_fido2.so` is executed to try
and authenticate with no username (this happens in e.g. the `login` file). If the authentication succeeds, authentication data is stored into the module's data and the username
is set automatically. The second invokation of `pam_fido2.so` will check to see if authentication data has already succeeded and confirms the authentication without
further action in this case.

### Client configuration
As most login systems currently ask for a user _before_ the PAM authentication process is started, you will probably need to tweak your
system a bit to make this work. If you use standard `getty` (i.e. terminal-based login) follow the instructions below. Otherwise, we'd love
to hear your success story!

#### getty + systemd

By default, `agetty(8)` (the program that runs on your `tty` and starts `login`) will prompt for a user _before_ `login` is started. The `-n` option to turn off this behaviour. If your system runs `getty` as a systemd unit (which is what the majority of systems do as of 2020), you can modify the unit and add the `-n` option as follows:

 * Copy the original systemd unit into the "custom units" folder /etc/systemd/system:
```
cp /lib/systemd/system/getty@.service /etc/systemd/system/
```

 * Add the '-n' parameter to the ExecStart line:
```diff
- ExecStart=-/sbin/agetty -o '-p -- \\u' --noclear %I $TERM
+ ExecStart=-/sbin/agetty -n -o '-p -- \\u' --noclear %I $TERM
```

 * Reload systemd (or restart your system).
