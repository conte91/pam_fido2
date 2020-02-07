project('pam_fido2', 'cpp')
cpp = meson.get_compiler('cpp')

fido2 = cpp.find_library('fido2')

#mytarget = custom_target('targetname',
  #input : 'cryptopp/GNUmakefile',
  #output : 'libcryptopp.a',
  #build_always_stale: true,
  #command : [find_program('build_cryptopp', dirs: ['.']), '@INPUT@', '@OUTDIR@']
#)

my_lib_cargs = []
if not cpp.has_header('cryptopp/cryptlib.h')
  error('Could not find crypto++')
endif
cryptopp = cpp.find_library('cryptopp')
#cryptopp = declare_dependency(link_with: cryptopp_lib)

util = library('util', ['src/util.cpp', 'src/hex.cpp'], dependencies: [cryptopp])

keystore = library('keystore', ['src/Assertion.cpp', 'src/KeyStore.cpp'], dependencies: [cryptopp, fido2], link_with: [util])

executable('test_authenticate', 'src/test_authenticate.cpp', dependencies: [fido2], link_with: [keystore, util])
executable('test_keys', 'src/test_keys.cpp', link_with: [util, keystore])

