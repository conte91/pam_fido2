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

#mytarget = custom_target('targetname',
  #input : 'cryptopp/GNUmakefile',
  #output : 'libcryptopp.a',
  #build_always_stale: true,
  #command : [find_program('build_cryptopp', dirs: ['.']), '@INPUT@', '@OUTDIR@']
#)

if not cpp.has_header('cryptopp/cryptlib.h')
  error('Could not find crypto++')
endif
cryptopp = cpp.find_library('cryptopp')
#cryptopp = declare_dependency(link_with: cryptopp_lib)

openssl = dependency('openssl')
util = library('fido_util', ['src/util.cpp', 'src/hex.cpp'], dependencies: [cryptopp])

keystore = library('keystore', ['src/Credential.cpp', 'src/Assertion.cpp', 'src/KeyStore.cpp', 'src/UserId.cpp'], dependencies: [cryptopp, fido2, openssl], link_with: [util])

authenticator = library('authenticator', ['src/Authenticator.cpp', 'src/FidoDevList.cpp'], dependencies: [fido2, openssl], link_with: [keystore, util])
executable('test_authenticate', 'src/test_authenticate.cpp', dependencies: [fido2], link_with: [authenticator, keystore, util])
executable('test_keys', 'src/test_keys.cpp', link_with: [util, keystore])

pam = cpp.find_library('pam')
pam_fido2 = library('pam_fido2', ['src/pam.cpp'], dependencies: [pam, fido2, openssl], link_with: [authenticator, keystore, util])
pam_fido2_user = library('pam_fido2_user', ['src/pam_select_user.cpp'], dependencies: [pam, fido2, openssl], link_with: [authenticator, keystore, util])
