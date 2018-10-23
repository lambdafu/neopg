# NeoPG - tests
#   Copyright 2017 The NeoPG developers
#
# NeoPG is released under the Simplified BSD License (see license.txt)

# libgpg-error

if(WIN32)
  set(GPG-ERROR-WIN32_SOURCES
    libgpg-error/src/w32-add.h
    libgpg-error/src/w32-estream.cpp
    libgpg-error/src/w32-lock.cpp
    libgpg-error/src/w32-thread.cpp)
endif()

add_library(gpg-error STATIC
  ${GPG-ERROR-WIN32_SOURCES}
  libgpg-error/src/gpg-error.h
  libgpg-error/src/b64dec.cpp
  libgpg-error/src/code-from-errno.cpp
  libgpg-error/src/code-to-errno.cpp
  libgpg-error/src/strerror.cpp
  libgpg-error/src/estream.h
  libgpg-error/src/estream.cpp
  libgpg-error/src/estream-printf.cpp
  libgpg-error/src/gpg-error.h
  libgpg-error/src/gpgrt-int.h
  libgpg-error/src/init.cpp
  libgpg-error/src/visibility.h
  libgpg-error/src/visibility.cpp
)


add_library(neopg::gpg-error ALIAS gpg-error)

target_include_directories(gpg-error PRIVATE
  libgpg-error/src
  ${CMAKE_BINARY_DIR}
)

add_executable(gpg-error-test
  libgpg-error/tests/t-b64dec.cpp
  libgpg-error/tests/t-printf.cpp
  libgpg-error/tests/t-strerror.cpp
  libgpg-error/tests/t-syserror.cpp
  libgpg-error/tests/gpg-error-test.cpp
)
target_include_directories(gpg-error-test PRIVATE
  libgpg-error/src
  ${CMAKE_BINARY_DIR}
)
target_link_libraries(gpg-error-test PRIVATE
  neopg::gpg-error
  GTest::GTest
  GTest::Main
)

add_test(GpgErrorTest gpg-error-test COMMAND gpg-error-test test_xml_output --gtest_output=xml:gpg-error-test.xml)

# libassuan

if(WIN32)
  set(ASSUAN_SYSTEM_CPP libassuan/src/system-w32.cpp)
else()
  set(ASSUAN_SYSTEM_CPP libassuan/src/system-posix.cpp)
endif()

add_library(assuan STATIC
  ${ASSUAN_SYSTEM_CPP}
  libassuan/src/assuan-buffer.cpp
  libassuan/src/assuan-defs.h
  libassuan/src/assuan-error.cpp
  libassuan/src/assuan-handler.cpp
  libassuan/src/assuan-inquire.cpp
  libassuan/src/assuan-io.cpp
  libassuan/src/assuan-listen.cpp
  libassuan/src/assuan-logging.cpp
  libassuan/src/assuan-pipe-connect.cpp
  libassuan/src/assuan-pipe-server.cpp
  libassuan/src/assuan-socket.cpp
  libassuan/src/assuan-uds.cpp
  libassuan/src/assuan.cpp
  libassuan/src/assuan.h
  libassuan/src/client.cpp
  libassuan/src/context.cpp
  libassuan/src/debug.cpp
  libassuan/src/debug.h
  libassuan/src/server.cpp
  libassuan/src/system.cpp
)

add_library(neopg::assuan ALIAS assuan)

target_include_directories(assuan PRIVATE
  libassuan/src
  libgpg-error/src
  ${CMAKE_BINARY_DIR}
)

target_compile_definitions(assuan PRIVATE
  HAVE_CONFIG_H=1
)

target_link_libraries(assuan PRIVATE
  neopg::gpg-error
)

add_executable(assuan-test
  libassuan/tests/fdpassing.cpp
  libassuan/tests/assuan-test.cpp
)
target_include_directories(assuan-test PRIVATE
  libassuan/src
  libgpg-error/src
)
target_compile_definitions(assuan-test PRIVATE
  CMAKE_SOURCE_DIR="${CMAKE_SOURCE_DIR}/legacy/libassuan/tests"
)
target_link_libraries(assuan-test PRIVATE
  neopg::assuan
  GTest::GTest
  GTest::Main
)

add_test(AssuanTest assuan-test COMMAND assuan-test test_xml_output --gtest_output=xml:assuan-test.xml)
add_dependencies(tests assuan-test)

# libgcrypt

add_library(gcrypt STATIC
  libgcrypt/src/cipher-proto.h
  libgcrypt/src/cipher.h
  libgcrypt/src/context.cpp
  libgcrypt/src/context.h
  libgcrypt/src/ec-context.h
  libgcrypt/src/g10lib.h
  libgcrypt/src/gcrypt-int.h
  libgcrypt/src/gcrypt-testapi.h
  libgcrypt/src/gcrypt.h
  libgcrypt/src/global.cpp
  libgcrypt/src/hmac256.cpp
  libgcrypt/src/hmac256.h
  libgcrypt/src/misc.cpp
  libgcrypt/src/mpi.h
  libgcrypt/src/secmem.cpp
  libgcrypt/src/secmem.h
  libgcrypt/src/sexp.cpp
  libgcrypt/src/stdmem.cpp
  libgcrypt/src/stdmem.h
  libgcrypt/src/types.h
  libgcrypt/src/visibility.cpp
  libgcrypt/src/visibility.h
  libgcrypt/cipher/crc.cpp
  libgcrypt/cipher/ecc.cpp
  libgcrypt/cipher/ecc-curves.cpp
  libgcrypt/cipher/ecc-eddsa.cpp
  libgcrypt/cipher/ecc-gost.cpp
  libgcrypt/cipher/ecc-misc.cpp
  libgcrypt/cipher/ecc-ecdsa.cpp
  libgcrypt/cipher/elgamal.cpp
  libgcrypt/cipher/des.cpp
  libgcrypt/cipher/dsa.cpp
  libgcrypt/cipher/rsa.cpp
  libgcrypt/cipher/sha1.cpp
  libgcrypt/cipher/sha256.cpp
  libgcrypt/cipher/sha512.cpp
  libgcrypt/cipher/keccak.cpp
  libgcrypt/cipher/whirlpool.cpp
  libgcrypt/cipher/md4.cpp
  libgcrypt/cipher/md5.cpp
  libgcrypt/cipher/rmd160.cpp
  libgcrypt/cipher/blowfish.cpp
  libgcrypt/cipher/camellia.cpp
  libgcrypt/cipher/camellia-glue.cpp
  libgcrypt/cipher/rijndael.cpp
  libgcrypt/cipher/idea.cpp
  libgcrypt/cipher/cast5.cpp
  libgcrypt/cipher/twofish.cpp
  libgcrypt/cipher/rfc2268.cpp
  libgcrypt/cipher/mac-cmac.cpp
  libgcrypt/cipher/cipher.cpp
  libgcrypt/cipher/cipher-internal.h
  libgcrypt/cipher/cipher-cbc.cpp
  libgcrypt/cipher/cipher-cfb.cpp
  libgcrypt/cipher/cipher-ofb.cpp
  libgcrypt/cipher/cipher-ctr.cpp
  libgcrypt/cipher/cipher-aeswrap.cpp
  libgcrypt/cipher/cipher-ccm.cpp
  libgcrypt/cipher/cipher-cmac.cpp
  libgcrypt/cipher/cipher-gcm.cpp
  libgcrypt/cipher/cipher-poly1305.cpp
  libgcrypt/cipher/cipher-ocb.cpp
  libgcrypt/cipher/cipher-xts.cpp
  libgcrypt/cipher/cipher-selftest.cpp
  libgcrypt/cipher/cipher-selftest.h
  libgcrypt/cipher/pubkey.cpp
  libgcrypt/cipher/pubkey-internal.h
  libgcrypt/cipher/pubkey-util.cpp
  libgcrypt/cipher/md.cpp
  libgcrypt/cipher/mac.cpp
  libgcrypt/cipher/mac-internal.h
  libgcrypt/cipher/mac-hmac.cpp
  libgcrypt/cipher/mac-cmac.cpp
  libgcrypt/cipher/mac-gmac.cpp
  libgcrypt/cipher/mac-poly1305.cpp
  libgcrypt/cipher/poly1305.cpp
  libgcrypt/cipher/poly1305-internal.h
  libgcrypt/cipher/kdf.cpp
  libgcrypt/cipher/scrypt.cpp
  libgcrypt/cipher/kdf-internal.h
  libgcrypt/cipher/bithelp.h
  libgcrypt/cipher/bufhelp.h
  libgcrypt/cipher/primegen.cpp
  libgcrypt/cipher/hash-common.cpp
  libgcrypt/cipher/hash-common.h
  libgcrypt/cipher/dsa-common.cpp
  libgcrypt/cipher/rsa-common.cpp
  libgcrypt/cipher/sha1.h
  libgcrypt/mpi/ec.cpp
  libgcrypt/mpi/mpi-add.cpp
  libgcrypt/mpi/mpi-bit.cpp
  libgcrypt/mpi/mpi-cmp.cpp
  libgcrypt/mpi/mpicoder.cpp
  libgcrypt/mpi/mpi-div.cpp
  libgcrypt/mpi/mpi-gcd.cpp
  libgcrypt/mpi/mpih-div.cpp
  libgcrypt/mpi/mpih-mul.cpp
  libgcrypt/mpi/mpi-inline.cpp
  libgcrypt/mpi/mpi-inv.cpp
  libgcrypt/mpi/mpi-mod.cpp
  libgcrypt/mpi/mpi-mpow.cpp
  libgcrypt/mpi/mpi-mul.cpp
  libgcrypt/mpi/mpi-pow.cpp
  libgcrypt/mpi/mpi-scan.cpp
  libgcrypt/mpi/mpiutil.cpp
  libgcrypt/mpi/mpih-add1.cpp
  libgcrypt/mpi/generic/mpih-lshift.cpp
  libgcrypt/mpi/generic/mpih-mul1.cpp
  libgcrypt/mpi/generic/mpih-mul2.cpp
  libgcrypt/mpi/generic/mpih-mul3.cpp
  libgcrypt/mpi/generic/mpih-rshift.cpp
  libgcrypt/mpi/generic/mpih-sub1.cpp
  libgcrypt/random/random.cpp
)
add_library(neopg::gcrypt ALIAS gcrypt)

target_include_directories(gcrypt PRIVATE
  libgcrypt/mpi
  libgcrypt/src
  libgpg-error/src
  ${CMAKE_BINARY_DIR}
)

target_link_libraries(gcrypt PRIVATE
  neopg::gpg-error
  neopg::neopg
)

add_executable(gcrypt-test
  libgcrypt/tests/hmac.cpp
  libgcrypt/tests/gcrypt-test.cpp
)
target_include_directories(gcrypt-test PRIVATE
  libgcrypt/src
  libgpg-error/src
)
target_link_libraries(gcrypt-test PRIVATE
  neopg::gcrypt
  GTest::GTest
  GTest::Main
)

add_test(GcryptTest gcrypt-test COMMAND gcrypt-test test_xml_output --gtest_output=xml:gcrypt-test.xml)
add_dependencies(tests gcrypt-test)

add_executable(gcrypt-secmem-test
  libgcrypt/tests/t-secmem.cpp
  libgcrypt/tests/gcrypt-secmem-test.cpp
)
target_include_directories(gcrypt-secmem-test PRIVATE
  libgpg-error/src
  libgcrypt/src
  ${CMAKE_BINARY_DIR}
)
target_link_libraries(gcrypt-secmem-test PRIVATE
  neopg::gcrypt
  GTest::GTest
  GTest::Main
)

add_test(GcryptSecmemTest gcrypt-secmem-test COMMAND gcrypt-secmem-test test_xml_output --gtest_output=xml:gcrypt-secmem-test.xml)
add_dependencies(tests gcrypt-secmem-test)

# libksba

add_library(ksba STATIC
  libksba/src/ksba.h
  libksba/src/reader.cpp
  libksba/src/writer.cpp
  libksba/src/asn1-parse.cpp
  libksba/src/asn1-func.cpp
  libksba/src/asn1-func2.cpp
  libksba/src/ber-help.cpp
  libksba/src/ber-decoder.cpp
  libksba/src/der-encoder.cpp
  libksba/src/cert.cpp
  libksba/src/cms.cpp
  libksba/src/cms-parser.cpp
  libksba/src/crl.cpp
  libksba/src/certreq.cpp
  libksba/src/ocsp.cpp
  libksba/src/keyinfo.cpp
  libksba/src/oid.cpp
  libksba/src/name.cpp
  libksba/src/dn.cpp
  libksba/src/time.cpp
  libksba/src/util.cpp
  libksba/src/asn1-tables.cpp
)
add_library(neopg::ksba ALIAS ksba)

target_include_directories(ksba PRIVATE
  libksba/src
  libgpg-error/src
  ${CMAKE_BINARY_DIR}
)
target_link_libraries(ksba PRIVATE
  neopg::gpg-error
  PkgConfig::botan-2
)

add_executable(ksba-test
  libksba/tests/ksba-test.cpp
  libksba/tests/t-oid.cpp
  libksba/tests/t-crl-parser.cpp
  libksba/tests/t-dnparser.cpp
  )
target_compile_definitions(ksba-test PRIVATE
  CMAKE_SOURCE_DIR="${CMAKE_SOURCE_DIR}/legacy/libksba/tests"
)
target_include_directories(ksba-test PRIVATE
  libgpg-error/src
  libksba/src
)
target_link_libraries(ksba-test PRIVATE
  neopg::ksba
  GTest::GTest
  GTest::Main
)
add_test(KsbaTest ksba-test COMMAND ksba-test test_xml_output --gtest_output=xml:ksba-test.xml)
add_dependencies(tests ksba-test)
