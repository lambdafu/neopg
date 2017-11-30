# NeoPG - tests
#   Copyright 2017 The NeoPG developers
#
# NeoPG is released under the Simplified BSD License (see license.txt)

FIND_PACKAGE(Boost COMPONENTS date_time locale REQUIRED)

add_executable(neopg
  ../legacy/gnupg/common/logging.h
  ../legacy/gnupg/common/logging.cpp
  ../legacy/gnupg/common/sysutils.h
  ../legacy/gnupg/common/sysutils.cpp
  ../legacy/gnupg/common/utf8conv.h
  ../legacy/gnupg/common/utf8conv.cpp
  ../legacy/gnupg/common/stringhelp.h
  ../legacy/gnupg/common/stringhelp.cpp
  ../legacy/gnupg/common/server-help.h
  ../legacy/gnupg/common/server-help.cpp
  ../legacy/gnupg/common/argparse.h
  ../legacy/gnupg/common/argparse.cpp
  ../legacy/gnupg/common/strlist.h
  ../legacy/gnupg/common/strlist.cpp
  ../legacy/gnupg/common/membuf.h
  ../legacy/gnupg/common/membuf.cpp
  ../legacy/gnupg/common/status.h
  ../legacy/gnupg/common/status.cpp
  ../legacy/gnupg/common/iobuf.h
  ../legacy/gnupg/common/iobuf.cpp
  ../legacy/gnupg/common/gettime.h
  ../legacy/gnupg/common/gettime.cpp
  ../legacy/gnupg/common/asshelp.h
  ../legacy/gnupg/common/asshelp.cpp
  ../legacy/gnupg/common/dotlock.h
  ../legacy/gnupg/common/dotlock.cpp
  ../legacy/gnupg/common/mischelp.h
  ../legacy/gnupg/common/compliance.h
  ../legacy/gnupg/common/compliance.cpp
  ../legacy/gnupg/common/exechelp.h
  ../legacy/gnupg/common/exechelp-posix.cpp
  ../legacy/gnupg/common/userids.h
  ../legacy/gnupg/common/userids.cpp
  ../legacy/gnupg/common/mbox-util.h
  ../legacy/gnupg/common/mbox-util.cpp
  ../legacy/gnupg/common/recsel.h
  ../legacy/gnupg/common/recsel.cpp
  ../legacy/gnupg/common/gpgrlhelp.cpp
  ../legacy/gnupg/common/homedir.cpp
  ../legacy/gnupg/common/miscellaneous.cpp
  ../legacy/gnupg/common/init.cpp
  ../legacy/gnupg/common/percent.cpp
  ../legacy/gnupg/common/zb32.cpp
  ../legacy/gnupg/common/openpgp-oid.cpp
  ../legacy/gnupg/common/ttyio.cpp
  ../legacy/gnupg/common/xasprintf.cpp
  ../legacy/gnupg/common/yesno.cpp
  ../legacy/gnupg/common/sexputil.cpp
  ../legacy/gnupg/common/tlv.cpp
  ../legacy/gnupg/common/util.h
  ../legacy/gnupg/common/convert.cpp
  ../legacy/gnupg/common/b64enc.cpp
  ../legacy/gnupg/kbx/keybox-init.cpp
  ../legacy/gnupg/kbx/keybox-util.cpp
  ../legacy/gnupg/kbx/keybox-blob.cpp
  ../legacy/gnupg/kbx/keybox-file.cpp
  ../legacy/gnupg/kbx/keybox-openpgp.cpp
  ../legacy/gnupg/kbx/keybox-update.cpp
  ../legacy/gnupg/kbx/keybox-search.cpp
  ../legacy/gnupg/g10/misc.cpp
  ../legacy/gnupg/g10/keyid.cpp
  ../legacy/gnupg/g10/keyserver.cpp
  ../legacy/gnupg/g10/pubkey-enc.cpp
  ../legacy/gnupg/g10/pkclist.cpp
  ../legacy/gnupg/g10/ecdh.cpp
  ../legacy/gnupg/g10/kbnode.cpp
  ../legacy/gnupg/g10/compress.cpp
  ../legacy/gnupg/g10/filter.h
  ../legacy/gnupg/g10/passphrase.cpp
  ../legacy/gnupg/g10/import.cpp
  ../legacy/gnupg/g10/export.cpp
  ../legacy/gnupg/g10/decrypt-data.cpp
  ../legacy/gnupg/g10/plaintext.cpp
  ../legacy/gnupg/g10/textfilter.cpp
  ../legacy/gnupg/g10/progress.cpp
  ../legacy/gnupg/g10/mdfilter.cpp
  ../legacy/gnupg/g10/seskey.cpp
  ../legacy/gnupg/g10/pkglue.cpp
  ../legacy/gnupg/g10/revoke.cpp
  ../legacy/gnupg/g10/sign.cpp
  ../legacy/gnupg/g10/encrypt.cpp
  ../legacy/gnupg/g10/decrypt.cpp
  ../legacy/gnupg/g10/cipher.cpp
  ../legacy/gnupg/g10/verify.cpp
  ../legacy/gnupg/g10/skclist.cpp
  ../legacy/gnupg/g10/keygen.cpp
  ../legacy/gnupg/g10/call-dirmngr.cpp
  ../legacy/gnupg/g10/call-agent.cpp
  ../legacy/gnupg/g10/getkey.cpp
  ../legacy/gnupg/g10/keydb.cpp
  ../legacy/gnupg/g10/packet.h
  ../legacy/gnupg/g10/build-packet.cpp
  ../legacy/gnupg/g10/parse-packet.cpp
  ../legacy/gnupg/g10/mainproc.cpp
  ../legacy/gnupg/g10/free-packet.cpp
  ../legacy/gnupg/g10/sig-check.cpp
  ../legacy/gnupg/g10/keyedit.cpp
  ../legacy/gnupg/g10/trust.cpp
  ../legacy/gnupg/g10/cpr.cpp
  ../legacy/gnupg/g10/keylist.cpp
  ../legacy/gnupg/g10/openfile.cpp
  ../legacy/gnupg/g10/key-check.cpp
  ../legacy/gnupg/g10/armor.cpp
  ../legacy/gnupg/g10/trustdb.cpp
  ../legacy/gnupg/g10/tdbio.cpp
  ../legacy/gnupg/g10/tdbdump.cpp
  ../legacy/gnupg/g10/delkey.cpp
  ../legacy/gnupg/g10/card-util.cpp
  ../legacy/gnupg/g10/gpg.cpp

  ../legacy/gnupg/agent/command.cpp
  ../legacy/gnupg/agent/gpg-agent.cpp
  ../legacy/gnupg/agent/protect.cpp
  ../legacy/gnupg/agent/call-scd.cpp
  ../legacy/gnupg/agent/findkey.cpp
  ../legacy/gnupg/agent/cvt-openpgp.cpp
  ../legacy/gnupg/agent/cache.cpp
  ../legacy/gnupg/agent/genkey.cpp
  ../legacy/gnupg/agent/call-pinentry.cpp
  ../legacy/gnupg/agent/trustlist.cpp
  ../legacy/gnupg/common/asshelp2.cpp
  ../legacy/gnupg/common/asshelp.h
  ../legacy/gnupg/agent/pkdecrypt.cpp
  ../legacy/gnupg/agent/pksign.cpp
  ../legacy/gnupg/agent/learncard.cpp
  ../legacy/gnupg/agent/divert-scd.cpp
  ../legacy/gnupg/common/name-value.cpp

  ../legacy/gnupg/dirmngr/dirmngr.cpp
  ../legacy/gnupg/dirmngr/crlfetch.cpp
  ../legacy/gnupg/dirmngr/dirmngr-client.cpp
  ../legacy/gnupg/dirmngr/dirmngr.cpp
  ../legacy/gnupg/dirmngr/dns-stuff.cpp
  ../legacy/gnupg/dirmngr/http-common.cpp
  ../legacy/gnupg/dirmngr/http.cpp
  ../legacy/gnupg/dirmngr/ks-action.cpp
  ../legacy/gnupg/dirmngr/ks-engine-hkp.cpp
  ../legacy/gnupg/dirmngr/ks-engine-http.cpp
  ../legacy/gnupg/dirmngr/ks-engine-kdns.cpp
  ../legacy/gnupg/dirmngr/misc.cpp
  ../legacy/gnupg/dirmngr/ocsp.cpp
  ../legacy/gnupg/dirmngr/server.cpp
  ../legacy/gnupg/dirmngr/validate.cpp
  ../legacy/gnupg/dirmngr/crlcache.cpp
  ../legacy/gnupg/dirmngr/certcache.cpp
  ../legacy/gnupg/dirmngr/cdblib.cpp
  ../legacy/gnupg/common/ksba-io-support.cpp

  ../legacy/gnupg/sm/call-agent.cpp
  ../legacy/gnupg/sm/certcheck.cpp
  ../legacy/gnupg/sm/certreqgen.cpp
  ../legacy/gnupg/sm/delete.cpp
  ../legacy/gnupg/sm/fingerprint.cpp
  ../legacy/gnupg/sm/sign.cpp
  ../legacy/gnupg/sm/call-dirmngr.cpp
  ../legacy/gnupg/sm/certdump.cpp
  ../legacy/gnupg/sm/certreqgen-ui.cpp
  ../legacy/gnupg/sm/encrypt.cpp
  ../legacy/gnupg/sm/gpgsm.cpp
  ../legacy/gnupg/sm/import.cpp
  ../legacy/gnupg/sm/keylist.cpp
  ../legacy/gnupg/sm/misc.cpp
  ../legacy/gnupg/sm/verify.cpp
  ../legacy/gnupg/sm/certchain.cpp
  ../legacy/gnupg/sm/certlist.cpp
  ../legacy/gnupg/sm/decrypt.cpp
  ../legacy/gnupg/sm/export.cpp
  ../legacy/gnupg/sm/keydb.cpp
  ../legacy/gnupg/sm/minip12.cpp
  ../legacy/gnupg/sm/passphrase.cpp
  ../legacy/gnupg/sm/server.cpp
  ../legacy/gnupg/sm/gpgsm.cpp

  ../legacy/gnupg/scd/scdaemon.cpp
  ../legacy/gnupg/scd/apdu.cpp
  ../legacy/gnupg/scd/app.cpp
  ../legacy/gnupg/scd/app-dinsig.cpp
  ../legacy/gnupg/scd/app-help.cpp
  ../legacy/gnupg/scd/app-nks.cpp
  ../legacy/gnupg/scd/app-p15.cpp
  ../legacy/gnupg/scd/app-sc-hsm.cpp
  ../legacy/gnupg/scd/app-openpgp.cpp
  ../legacy/gnupg/scd/atr.cpp
  ../legacy/gnupg/scd/ccid-driver.cpp
  ../legacy/gnupg/scd/command.cpp
  ../legacy/gnupg/scd/iso7816.cpp

  ../include/neopg/cli/command.h
  ../include/neopg/cli/version_command.h
  ../include/neopg/cli/packet_command.h
  ../include/neopg/cli/random_command.h
  ../include/neopg/cli/hash_command.h
  ../include/neopg/cli/armor_command.h
  ../include/neopg/cli/cat_command.h
  ../include/neopg/cli/compress_command.h
  cli/command.cpp
  cli/version_command.cpp
  cli/packet_command.cpp
  cli/random_command.cpp
  cli/hash_command.cpp
  cli/armor_command.cpp
  cli/cat_command.cpp
  cli/compress_command.cpp
  neopg.cpp
)
target_include_directories(neopg PRIVATE
  ../legacy/libgpg-error/src
  ../legacy/libassuan/src
  ../legacy/libgcrypt/src
  ../legacy/npth/src
  ../legacy/libksba/src
  ${CMAKE_BINARY_DIR}/.
  ${Boost_INCLUDE_DIR}
  ${SQLITE3_INCLUDE_DIRS}
  ${BOTAN2_INCLUDE_DIRS}
  ${LIBUSB_INCLUDE_DIRS}
  ${GNUTLS_INCLUDE_DIRS}
  ${RANG_INCLUDE_DIR}
  ${CLI11_INCLUDE_DIR}
  ${JSON_INCLUDE_DIR}
  ../include
)
target_compile_definitions(neopg PRIVATE
  HAVE_CONFIG_H=1
  CMAKE_INSTALL_PREFIX="${CMAKE_INSTALL_PREFIX}")

target_link_libraries(neopg PRIVATE
  gpg-error
  assuan
  gcrypt
  npth
  ksba
${Boost_LIBRARIES}
${SQLITE3_LDFLAGS} ${SQLITE3_LIBRARIES}
${BOTAN2_LDFLAGS} ${BOTAN2_LIBRARIES}
${LIBUSB_LDFLAGS} ${LIBUSB_LIBRARIES}
${GNUTLS_LDFLAGS} ${GNUTLS_LIBRARIES}
 -lresolv -lz -lbz2
 libneopg
)
target_compile_options(neopg PUBLIC
${SQLITE3_CFLAGS_OTHER}
${BOTAN2_CFLAGS_OTHER})

# Locale

add_subdirectory(locale)

SET(_potFile neopg.pot)
SET(_xgettext_option_list
  -cTranslators
  --msgid-bugs-address="https://github.com/das-labor/neopg"
  --package-version "${PROJECT_VERSION}"
  --package-name NeoPG
  --copyright "The NeoPG Developers"
  -d neopg
  --boost
  --keyword=_
)

# get_target_property(_src_list neopg SOURCES)
SET(_src_list neopg.cpp)

ADD_CUSTOM_COMMAND(OUTPUT ${_potFile}
    COMMAND ${XGETTEXT_CMD} ${_xgettext_option_list} -o locale/${_potFile} ${_src_list}
    DEPENDS ${_src_list}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    COMMENT "Extract translatable messages to ${_potFile}"
)

ADD_CUSTOM_TARGET(update-pot ${_all}
DEPENDS ${_potFile}
)
