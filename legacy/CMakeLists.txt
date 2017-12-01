# NeoPG - tests
#   Copyright 2017 The NeoPG developers
#
# NeoPG is released under the Simplified BSD License (see license.txt)

# libgpg-error

add_library(gpg-error
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

if(WIN32)
  target_sources(gpg-error PRIVATE
    libgpg-error/src/w32-add.h
    libgpg-error/src/w32-estream.cpp
    libgpg-error/src/w32-lock.cpp
    libgpg-error/src/w32-thread.cpp
  )
endif()

add_library(neopg::gpg-error ALIAS gpg-error)

target_include_directories(gpg-error PRIVATE
  libgpg-error/src
  ${Intl_INCLUDE_DIRS}
  ${CMAKE_BINARY_DIR}/.)
target_compile_definitions(gpg-error PRIVATE
  HAVE_CONFIG_H=1)
target_link_libraries(gpg-error PRIVATE pthread
  ${Intl_LDFLAGS} ${Intl_LIBRARIES})
target_compile_options(gpg-error PRIVATE -fpermissive
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
  ${CMAKE_BINARY_DIR}/.)
target_link_libraries(gpg-error-test PRIVATE
  gpg-error
  GTest::GTest GTest::Main)
add_test(GpgErrorTest gpg-error-test COMMAND gpg-error-test test_xml_output --gtest_output=xml:gpg-error-test.xml)


# libassuan

add_library(assuan
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

if(WIN32)
  target_sources(assuan PRIVATE
    libassuan/src/system-w32.cpp
  )
else()
  target_sources(assuan PRIVATE
    libassuan/src/system-posix.cpp
)
endif()

target_compile_options(assuan PRIVATE -fpermissive
)

add_library(neopg::assuan ALIAS assuan)

target_include_directories(assuan PRIVATE
  libgpg-error/src
  libassuan/src
  ${CMAKE_BINARY_DIR}/.)
target_compile_definitions(assuan PRIVATE
  HAVE_CONFIG_H=1)
target_link_libraries(assuan PRIVATE gpg-error)

add_executable(assuan-test
  libassuan/tests/fdpassing.cpp
  libassuan/tests/assuan-test.cpp)
target_include_directories(assuan-test PRIVATE
  libgpg-error/src
  libassuan/src
  ${CMAKE_BINARY_DIR}/.)
target_compile_definitions(assuan-test PRIVATE
CMAKE_SOURCE_DIR="${CMAKE_SOURCE_DIR}/legacy/libassuan/tests")
target_compile_options(assuan-test PRIVATE -fpermissive
)
target_link_libraries(assuan-test PRIVATE
  assuan
  GTest::GTest GTest::Main)
add_test(AssuanTest assuan-test COMMAND assuan-test test_xml_output --gtest_output=xml:assuan-test.xml)

# libgcrypt

add_library(gcrypt
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
  libgcrypt/src/hwf-common.h
  libgcrypt/src/hwf-x86.cpp
  libgcrypt/src/hwfeatures.cpp
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
  libgcrypt/mpi/generic/udiv-w-sdiv.cpp
  libgcrypt/random/random.cpp
)
add_library(neopg::gcrypt ALIAS gcrypt)

target_include_directories(gcrypt PRIVATE
  libgpg-error/src
  libgcrypt/mpi
  libgcrypt/src
  ../include
  ${BOTAN2_INCLUDE_DIRS}
  ${CMAKE_BINARY_DIR}/.)
target_compile_definitions(gcrypt PRIVATE
  HAVE_CONFIG_H=1)
target_link_libraries(gcrypt PRIVATE
  ${BOTAN2_LDFLAGS} ${BOTAN2_LIBRARIES}
  libneopg)
target_compile_options(gcrypt PRIVATE
 -fpermissive
 ${BOTAN2_CFLAGS_OTHER})

add_executable(gcrypt-test
  libgcrypt/tests/hmac.cpp
  libgcrypt/tests/gcrypt-test.cpp)
target_include_directories(gcrypt-test PRIVATE
  libgpg-error/src
  libgcrypt/src
  ${CMAKE_BINARY_DIR}/.)
target_compile_options(gcrypt-test PRIVATE -fpermissive -Wnarrowing
)
target_link_libraries(gcrypt-test PRIVATE
  gcrypt
  gpg-error
  GTest::GTest GTest::Main)
add_test(GcryptTest gcrypt-test COMMAND gcrypt-test test_xml_output --gtest_output=xml:gcrypt-test.xml)

add_executable(gcrypt-secmem-test
  libgcrypt/tests/t-secmem.cpp
  libgcrypt/tests/gcrypt-secmem-test.cpp)
target_include_directories(gcrypt-secmem-test PRIVATE
    libgpg-error/src
    libgcrypt/src
    ${CMAKE_BINARY_DIR}/.)
target_compile_options(gcrypt-secmem-test PRIVATE -fpermissive
)
  target_link_libraries(gcrypt-secmem-test PRIVATE
    gcrypt
    gpg-error
    GTest::GTest GTest::Main)
  add_test(GcryptSecmemTest gcrypt-secmem-test COMMAND gcrypt-secmem-test test_xml_output --gtest_output=xml:gcrypt-secmem-test.xml)

# libksba

add_library(ksba
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
  libgpg-error/src
  libksba/src
  ${CMAKE_BINARY_DIR}/.
  ${BOTAN2_INCLUDE_DIRS})
target_link_libraries(ksba PRIVATE
  gpg-error
  ${BOTAN2_LDFLAGS} ${BOTAN2_LIBRARIES})
target_compile_definitions(ksba PRIVATE
  HAVE_CONFIG_H=1
  ${BOTAN2_CFLAGS_OTHER}
)

target_compile_options(ksba PRIVATE -fpermissive
)

add_executable(ksba-test
  libksba/tests/ksba-test.cpp
  libksba/tests/t-oid.cpp
  libksba/tests/t-crl-parser.cpp
  libksba/tests/t-dnparser.cpp
  )
target_include_directories(ksba-test PRIVATE
  libgpg-error/src
  libksba/src
  ${CMAKE_BINARY_DIR}/.)
target_compile_definitions(ksba-test PRIVATE
  CMAKE_SOURCE_DIR="${CMAKE_SOURCE_DIR}/legacy/libksba/tests")
target_link_libraries(ksba-test PRIVATE
  gpg-error
  ksba
  GTest::GTest GTest::Main)
add_test(KsbaTest ksba-test COMMAND ksba-test test_xml_output --gtest_output=xml:ksba-test.xml)
