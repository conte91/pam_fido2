project('pam_fido2', 'cpp')
cpp = meson.get_compiler('cpp')

#fido2 = cpp.find_library('fido2')
cmake = import('cmake')
# Configure the CMake project
fido2_proj = cmake.subproject('libfido2')

# Fetch the dependency object
cbor = cpp.find_library('cbor')
udev = cpp.find_library('udev')
fido2_lib = fido2_proj.dependency('fido2')
fido2 = declare_dependency(dependencies: [fido2_lib, cbor, udev])

openssl = dependency('openssl')
util = static_library('fido_util', ['src/util.cpp', 'src/hex.cpp'])

keystore = static_library('keystore', ['src/Credential.cpp', 'src/Assertion.cpp', 'src/KeyStore.cpp', 'src/UserId.cpp'], dependencies: [fido2, openssl], link_with: [util])

authenticator = static_library('authenticator', ['src/Authenticator.cpp', 'src/Config.cpp', 'src/DeviceHandle.cpp', 'src/FidoDevList.cpp'], dependencies: [fido2, openssl], link_with: [keystore, util])
fido2_tool = executable('fido2_tool', 'src/fido2_tool.cpp', dependencies: [fido2], link_with: [authenticator, keystore, util])
executable('test_keys', 'src/test_keys.cpp', dependencies: [fido2], link_with: [util, keystore])

pam = cpp.find_library('pam')
pam_fido2 = library('pam_fido2', ['src/pam.cpp'], dependencies: [pam, fido2, openssl], link_with: [authenticator, keystore, util])

meson.source_root()

ubuntu_build_script = vcs_tag(command: './dist/get_vcs_tag', input: './dist/ubuntu/build_ubuntu_pkg.in', output: 'build_ubuntu_pkg')
ubuntu_pkg = custom_target('pam-fido2_ubuntu.deb',
		output : 'pam-fido2_ubuntu.deb',
		input : [ubuntu_build_script, pam_fido2, fido2_tool, './dist/ubuntu/after-install', './dist/ubuntu/after-remove'],
		command : ['sh', ubuntu_build_script, meson.source_root(), '@OUTDIR@']
		)
