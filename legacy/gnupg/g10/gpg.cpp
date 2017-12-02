/* gpg.c - The GnuPG utility (main for gpg)
 * Copyright (C) 1998-2011 Free Software Foundation, Inc.
 * Copyright (C) 1997-2017 Werner Koch
 * Copyright (C) 2015-2017 g10 Code GmbH
 *
 * This file is part of GnuPG.
 *
 * GnuPG is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * GnuPG is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 */

#include <config.h>
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#ifdef HAVE_STAT
#include <sys/stat.h> /* for stat() */
#endif
#include <fcntl.h>
#ifdef HAVE_W32_SYSTEM
#ifdef HAVE_WINSOCK2_H
#include <winsock2.h>
#endif
#include <windows.h>
#endif

#include <boost/algorithm/string/join.hpp>
#include <sstream>

#include <assuan.h>
#include "../common/asshelp.h"
#include "../common/compliance.h"
#include "../common/init.h"
#include "../common/iobuf.h"
#include "../common/mbox-util.h"
#include "../common/status.h"
#include "../common/sysutils.h"
#include "../common/ttyio.h"
#include "../common/util.h"
#include "call-dirmngr.h"
#include "filter.h"
#include "gpg.h"
#include "keydb.h"
#include "keyserver-internal.h"
#include "main.h"
#include "options.h"
#include "packet.h"
#include "trustdb.h"

#if defined(HAVE_DOSISH_SYSTEM) || defined(__CYGWIN__)
#define MY_O_BINARY O_BINARY
#ifndef S_IRGRP
#define S_IRGRP 0
#define S_IWGRP 0
#endif
#else
#define MY_O_BINARY 0
#endif

#ifdef __MINGW32__
int _dowildcard = -1;
#endif

struct options opt;
struct glo_ctrl glo_ctrl;

int memory_debug_mode;
int memory_stat_debug_mode;

std::string str_to_utf8(const char *string, int is_utf8) {
  if (is_utf8)
    return string;
  else {
    return native_to_utf8(string);
  }
}

enum cmd_and_opt_values {
  aNull = 0,
  oArmor = 'a',
  aDetachedSign = 'b',
  aSym = 'c',
  aDecrypt = 'd',
  aEncr = 'e',
  oRecipientFile = 'f',
  oHiddenRecipientFile = 'F',
  oInteractive = 'i',
  aListKeys = 'k',
  oDryRun = 'n',
  oOutput = 'o',
  oQuiet = 'q',
  oRecipient = 'r',
  oHiddenRecipient = 'R',
  aSign = 's',
  oTextmode = 't',
  oLocalUser = 'u',
  oVerbose = 'v',
  oCompress = 'z',
  oSetNotation = 'N',
  aListSecretKeys = 'K',
  oBatch = 500,
  oMaxOutput,
  oSigNotation,
  oCertNotation,
  aEncrFiles,
  aEncrSym,
  aDecryptFiles,
  aClearsign,
  aStore,
  aQuickKeygen,
  aFullKeygen,
  aKeygen,
  aSignEncr,
  aSignEncrSym,
  aSignSym,
  aSignKey,
  aLSignKey,
  aQuickSignKey,
  aQuickLSignKey,
  aQuickAddUid,
  aQuickAddKey,
  aQuickRevUid,
  aQuickSetExpire,
  aQuickSetPrimaryUid,
  aListPackets,
  aEditKey,
  aDeleteKeys,
  aDeleteSecretKeys,
  aDeleteSecretAndPublicKeys,
  aImport,
  aFastImport,
  aVerify,
  aVerifyFiles,
  aListSigs,
  aSendKeys,
  aRecvKeys,
  aLocateKeys,
  aSearchKeys,
  aRefreshKeys,
  aFetchKeys,
  aExport,
  aExportSecret,
  aExportSecretSub,
  aExportSshKey,
  aCheckKeys,
  aGenRevoke,
  aDesigRevoke,
  aCheckTrustDB,
  aUpdateTrustDB,
  aListTrustDB,
  aListTrustPath,
  aExportOwnerTrust,
  aImportOwnerTrust,
  aCardStatus,
  aCardEdit,
  aChangePIN,
  aPasswd,

  oMimemode,
  oNoTextmode,
  oExpert,
  oNoExpert,
  oDefSigExpire,
  oAskSigExpire,
  oNoAskSigExpire,
  oDefCertExpire,
  oAskCertExpire,
  oNoAskCertExpire,
  oDefCertLevel,
  oMinCertLevel,
  oAskCertLevel,
  oNoAskCertLevel,
  oFingerprint,
  oWithFingerprint,
  oWithSubkeyFingerprint,
  oWithICAOSpelling,
  oWithKeygrip,
  oWithSecret,
  oWithWKDHash,
  oWithColons,
  oWithKeyData,
  oWithSigList,
  oWithSigCheck,
  oAnswerYes,
  oAnswerNo,
  oKeyring,
  oPrimaryKeyring,
  oSecretKeyring,
  oDefaultKey,
  oDefRecipient,
  oDefRecipientSelf,
  oNoDefRecipient,
  oTrySecretKey,
  oOptions,
  oDebug,
  oDebugLevel,
  oDebugAll,
  oDebugIOLBF,
  oStatusFD,
  oStatusFile,
  oAttributeFD,
  oAttributeFile,
  oCompletesNeeded,
  oMarginalsNeeded,
  oMaxCertDepth,
  oCompliance,
  oGnuPG,
  oRFC4880,
  oRFC4880bis,
  oOpenPGP,
  oPGP6,
  oPGP7,
  oPGP8,
  oDE_VS,
  oCipherAlgo,
  oDigestAlgo,
  oCertDigestAlgo,
  oCompressAlgo,
  oPassphrase,
  oPassphraseFD,
  oPassphraseFile,
  oCommandFD,
  oCommandFile,
  oNoVerbose,
  oTrustDBName,
  oNoSecmemWarn,
  oRequireSecmem,
  oNoRequireSecmem,
  oNoPermissionWarn,
  oNoArmor,
  oNoDefKeyring,
  oNoKeyring,
  oNoTTY,
  oNoOptions,
  oNoBatch,
  oHomedir,
  oSkipVerify,
  oSkipHiddenRecipients,
  oNoSkipHiddenRecipients,
  oAlwaysTrust,
  oTrustModel,
  oForceOwnertrust,
  oSetFilename,
  oSetPolicyURL,
  oSigPolicyURL,
  oCertPolicyURL,
  oSigKeyserverURL,
  oComment,
  oDefaultComment,
  oNoComments,
  oThrowKeyids,
  oNoThrowKeyids,
  oS2KMode,
  oS2KDigest,
  oS2KCipher,
  oS2KCount,
  oKeyServer,
  oKeyServerOptions,
  oImportOptions,
  oImportFilter,
  oExportOptions,
  oExportFilter,
  oListOptions,
  oVerifyOptions,
  oEncryptTo,
  oHiddenEncryptTo,
  oNoEncryptTo,
  oEncryptToDefaultKey,
  oLoggerFD,
  oLoggerFile,
  oUtf8Strings,
  oNoUtf8Strings,
  oDisableCipherAlgo,
  oDisablePubkeyAlgo,
  oAllowFreeformUID,
  oNoAllowFreeformUID,
  oListOnly,
  oIgnoreTimeConflict,
  oIgnoreValidFrom,
  oIgnoreCrcError,
  oShowSessionKey,
  oOverrideSessionKey,
  oOverrideSessionKeyFD,
  oAutoKeyRetrieve,
  oNoAutoKeyRetrieve,
  oUseAgent,
  oNoUseAgent,
  oMergeOnly,
  oTryAllSecrets,
  oTrustedKey,
  oNoSigCache,
  oAutoCheckTrustDB,
  oNoAutoCheckTrustDB,
  oPreservePermissions,
  oDefaultPreferenceList,
  oDefaultKeyserverURL,
  oPersonalCipherPreferences,
  oPersonalDigestPreferences,
  oPersonalCompressPreferences,
  oLCctype,
  oLCmessages,
  oGroup,
  oUnGroup,
  oNoGroups,
  oEnableProgressFilter,
  oMultifile,
  oKeyidFormat,
  oExitOnStatusWriteError,
  oLimitCardInsertTries,
  oRequireCrossCert,
  oNoRequireCrossCert,
  oAutoKeyLocate,
  oNoAutoKeyLocate,
  oEnableLargeRSA,
  oDisableLargeRSA,
  oEnableDSA2,
  oDisableDSA2,
  oFakedSystemTime,
  oPrintDANERecords,
  oDefaultNewKeyAlgo,
  oWeakDigest,
  oUnwrap,
  oOnlySignTextIDs,
  oDisableSignerUID,
  oSender,

  oNoop
};

const static ARGPARSE_OPTS opts[] = {

    ARGPARSE_group(300, N_("@Commands:\n ")),

    ARGPARSE_c(aSign, "sign", N_("make a signature")),
    ARGPARSE_c(aClearsign, "clear-sign", N_("make a clear text signature")),
    ARGPARSE_c(aClearsign, "clearsign", "@"),
    ARGPARSE_c(aDetachedSign, "detach-sign", N_("make a detached signature")),
    ARGPARSE_c(aEncr, "encrypt", N_("encrypt data")),
    ARGPARSE_c(aEncrFiles, "encrypt-files", "@"),
    ARGPARSE_c(aSym, "symmetric", N_("encryption only with symmetric cipher")),
    ARGPARSE_c(aStore, "store", "@"),
    ARGPARSE_c(aDecrypt, "decrypt", N_("decrypt data (default)")),
    ARGPARSE_c(aDecryptFiles, "decrypt-files", "@"),
    ARGPARSE_c(aVerify, "verify", N_("verify a signature")),
    ARGPARSE_c(aVerifyFiles, "verify-files", "@"),
    ARGPARSE_c(aListKeys, "list-keys", N_("list keys")),
    ARGPARSE_c(aListKeys, "list-public-keys", "@"),
    ARGPARSE_c(aListSigs, "list-signatures", N_("list keys and signatures")),
    ARGPARSE_c(aListSigs, "list-sigs", "@"),
    ARGPARSE_c(aCheckKeys, "check-signatures",
               N_("list and check key signatures")),
    ARGPARSE_c(aCheckKeys, "check-sigs", "@"),
    ARGPARSE_c(oFingerprint, "fingerprint", N_("list keys and fingerprints")),
    ARGPARSE_c(aListSecretKeys, "list-secret-keys", N_("list secret keys")),
    ARGPARSE_c(aKeygen, "generate-key", N_("generate a new key pair")),
    ARGPARSE_c(aKeygen, "gen-key", "@"),
    ARGPARSE_c(aQuickKeygen, "quick-generate-key",
               N_("quickly generate a new key pair")),
    ARGPARSE_c(aQuickKeygen, "quick-gen-key", "@"),
    ARGPARSE_c(aQuickAddUid, "quick-add-uid", N_("quickly add a new user-id")),
    ARGPARSE_c(aQuickAddUid, "quick-adduid", "@"),
    ARGPARSE_c(aQuickAddKey, "quick-add-key", "@"),
    ARGPARSE_c(aQuickAddKey, "quick-addkey", "@"),
    ARGPARSE_c(aQuickRevUid, "quick-revoke-uid",
               N_("quickly revoke a user-id")),
    ARGPARSE_c(aQuickRevUid, "quick-revuid", "@"),
    ARGPARSE_c(aQuickSetExpire, "quick-set-expire",
               N_("quickly set a new expiration date")),
    ARGPARSE_c(aQuickSetPrimaryUid, "quick-set-primary-uid", "@"),
    ARGPARSE_c(aFullKeygen, "full-generate-key",
               N_("full featured key pair generation")),
    ARGPARSE_c(aFullKeygen, "full-gen-key", "@"),
    ARGPARSE_c(aGenRevoke, "generate-revocation",
               N_("generate a revocation certificate")),
    ARGPARSE_c(aGenRevoke, "gen-revoke", "@"),
    ARGPARSE_c(aDeleteKeys, "delete-keys",
               N_("remove keys from the public keyring")),
    ARGPARSE_c(aDeleteSecretKeys, "delete-secret-keys",
               N_("remove keys from the secret keyring")),
    ARGPARSE_c(aQuickSignKey, "quick-sign-key", N_("quickly sign a key")),
    ARGPARSE_c(aQuickLSignKey, "quick-lsign-key",
               N_("quickly sign a key locally")),
    ARGPARSE_c(aSignKey, "sign-key", N_("sign a key")),
    ARGPARSE_c(aLSignKey, "lsign-key", N_("sign a key locally")),
    ARGPARSE_c(aEditKey, "edit-key", N_("sign or edit a key")),
    ARGPARSE_c(aEditKey, "key-edit", "@"),
    ARGPARSE_c(aPasswd, "change-passphrase", N_("change a passphrase")),
    ARGPARSE_c(aPasswd, "passwd", "@"),
    ARGPARSE_c(aDesigRevoke, "generate-designated-revocation", "@"),
    ARGPARSE_c(aDesigRevoke, "desig-revoke", "@"),
    ARGPARSE_c(aExport, "export", N_("export keys")),
    ARGPARSE_c(aSendKeys, "send-keys", N_("export keys to a keyserver")),
    ARGPARSE_c(aRecvKeys, "receive-keys", N_("import keys from a keyserver")),
    ARGPARSE_c(aRecvKeys, "recv-keys", "@"),
    ARGPARSE_c(aSearchKeys, "search-keys",
               N_("search for keys on a keyserver")),
    ARGPARSE_c(aRefreshKeys, "refresh-keys",
               N_("update all keys from a keyserver")),
    ARGPARSE_c(aLocateKeys, "locate-keys", "@"),
    ARGPARSE_c(aFetchKeys, "fetch-keys", "@"),
    ARGPARSE_c(aExportSecret, "export-secret-keys", "@"),
    ARGPARSE_c(aExportSecretSub, "export-secret-subkeys", "@"),
    ARGPARSE_c(aExportSshKey, "export-ssh-key", "@"),
    ARGPARSE_c(aImport, "import", N_("import/merge keys")),
    ARGPARSE_c(aFastImport, "fast-import", "@"),
#ifdef ENABLE_CARD_SUPPORT
    ARGPARSE_c(aCardStatus, "card-status", N_("print the card status")),
    ARGPARSE_c(aCardEdit, "edit-card", N_("change data on a card")),
    ARGPARSE_c(aCardEdit, "card-edit", "@"),
    ARGPARSE_c(aChangePIN, "change-pin", N_("change a card's PIN")),
#endif
    ARGPARSE_c(aListPackets, "list-packets", "@"),

#ifndef NO_TRUST_MODELS
    ARGPARSE_c(aExportOwnerTrust, "export-ownertrust", "@"),
    ARGPARSE_c(aImportOwnerTrust, "import-ownertrust", "@"),
    ARGPARSE_c(aUpdateTrustDB, "update-trustdb",
               N_("update the trust database")),
    ARGPARSE_c(aCheckTrustDB, "check-trustdb", "@"),
#endif

    ARGPARSE_group(301, N_("@\nOptions:\n ")),

    ARGPARSE_s_n(oArmor, "armor", N_("create ascii armored output")),
    ARGPARSE_s_n(oArmor, "armour", "@"),

    ARGPARSE_s_s(oRecipient, "recipient", N_("|USER-ID|encrypt for USER-ID")),
    ARGPARSE_s_s(oHiddenRecipient, "hidden-recipient", "@"),
    ARGPARSE_s_s(oRecipientFile, "recipient-file", "@"),
    ARGPARSE_s_s(oHiddenRecipientFile, "hidden-recipient-file", "@"),
    ARGPARSE_s_s(oRecipient, "remote-user", "@"), /* (old option name) */
    ARGPARSE_s_s(oDefRecipient, "default-recipient", "@"),
    ARGPARSE_s_n(oDefRecipientSelf, "default-recipient-self", "@"),
    ARGPARSE_s_n(oNoDefRecipient, "no-default-recipient", "@"),

    ARGPARSE_s_s(oEncryptTo, "encrypt-to", "@"),
    ARGPARSE_s_n(oNoEncryptTo, "no-encrypt-to", "@"),
    ARGPARSE_s_s(oHiddenEncryptTo, "hidden-encrypt-to", "@"),
    ARGPARSE_s_n(oEncryptToDefaultKey, "encrypt-to-default-key", "@"),
    ARGPARSE_s_s(oLocalUser, "local-user",
                 N_("|USER-ID|use USER-ID to sign or decrypt")),
    ARGPARSE_s_s(oSender, "sender", "@"),

    ARGPARSE_s_s(oTrySecretKey, "try-secret-key", "@"),

    ARGPARSE_s_n(oMimemode, "mimemode", "@"),
    ARGPARSE_s_n(oTextmode, "textmode", N_("use canonical text mode")),
    ARGPARSE_s_n(oNoTextmode, "no-textmode", "@"),

    ARGPARSE_s_n(oExpert, "expert", "@"),
    ARGPARSE_s_n(oNoExpert, "no-expert", "@"),

    ARGPARSE_s_s(oDefSigExpire, "default-sig-expire", "@"),
    ARGPARSE_s_n(oAskSigExpire, "ask-sig-expire", "@"),
    ARGPARSE_s_n(oNoAskSigExpire, "no-ask-sig-expire", "@"),
    ARGPARSE_s_s(oDefCertExpire, "default-cert-expire", "@"),
    ARGPARSE_s_n(oAskCertExpire, "ask-cert-expire", "@"),
    ARGPARSE_s_n(oNoAskCertExpire, "no-ask-cert-expire", "@"),
    ARGPARSE_s_i(oDefCertLevel, "default-cert-level", "@"),
    ARGPARSE_s_i(oMinCertLevel, "min-cert-level", "@"),
    ARGPARSE_s_n(oAskCertLevel, "ask-cert-level", "@"),
    ARGPARSE_s_n(oNoAskCertLevel, "no-ask-cert-level", "@"),

    ARGPARSE_s_s(oOutput, "output", N_("|FILE|write output to FILE")),
    ARGPARSE_p_u(oMaxOutput, "max-output", "@"),

    ARGPARSE_s_n(oVerbose, "verbose", N_("verbose")),
    ARGPARSE_s_n(oQuiet, "quiet", "@"), ARGPARSE_s_n(oNoTTY, "no-tty", "@"),

    ARGPARSE_s_n(oDisableSignerUID, "disable-signer-uid", "@"),

    ARGPARSE_s_n(oDryRun, "dry-run", N_("do not make any changes")),
    ARGPARSE_s_n(oInteractive, "interactive", N_("prompt before overwriting")),

    ARGPARSE_s_n(oBatch, "batch", "@"), ARGPARSE_s_n(oAnswerYes, "yes", "@"),
    ARGPARSE_s_n(oAnswerNo, "no", "@"), ARGPARSE_s_s(oKeyring, "keyring", "@"),
    ARGPARSE_s_s(oPrimaryKeyring, "primary-keyring", "@"),
    ARGPARSE_s_s(oSecretKeyring, "secret-keyring", "@"),
    ARGPARSE_s_s(oDefaultKey, "default-key", "@"),

    ARGPARSE_s_s(oKeyServer, "keyserver", "@"),
    ARGPARSE_s_s(oKeyServerOptions, "keyserver-options", "@"),
    ARGPARSE_s_s(oImportOptions, "import-options", "@"),
    ARGPARSE_s_s(oImportFilter, "import-filter", "@"),
    ARGPARSE_s_s(oExportOptions, "export-options", "@"),
    ARGPARSE_s_s(oExportFilter, "export-filter", "@"),
    ARGPARSE_s_s(oListOptions, "list-options", "@"),
    ARGPARSE_s_s(oVerifyOptions, "verify-options", "@"),

    ARGPARSE_s_s(oOptions, "options", "@"),

    ARGPARSE_s_s(oDebug, "debug", "@"),
    ARGPARSE_s_s(oDebugLevel, "debug-level", "@"),
    ARGPARSE_s_n(oDebugAll, "debug-all", "@"),
    ARGPARSE_s_n(oDebugIOLBF, "debug-iolbf", "@"),
    ARGPARSE_s_i(oStatusFD, "status-fd", "@"),
    ARGPARSE_s_s(oStatusFile, "status-file", "@"),
    ARGPARSE_s_i(oAttributeFD, "attribute-fd", "@"),
    ARGPARSE_s_s(oAttributeFile, "attribute-file", "@"),

    ARGPARSE_s_i(oCompletesNeeded, "completes-needed", "@"),
    ARGPARSE_s_i(oMarginalsNeeded, "marginals-needed", "@"),
    ARGPARSE_s_i(oMaxCertDepth, "max-cert-depth", "@"),
    ARGPARSE_s_s(oTrustedKey, "trusted-key", "@"),

    ARGPARSE_s_s(oCompliance, "compliance", "@"),
    ARGPARSE_s_n(oGnuPG, "gnupg", "@"), ARGPARSE_s_n(oGnuPG, "no-pgp2", "@"),
    ARGPARSE_s_n(oGnuPG, "no-pgp6", "@"), ARGPARSE_s_n(oGnuPG, "no-pgp7", "@"),
    ARGPARSE_s_n(oGnuPG, "no-pgp8", "@"),
    ARGPARSE_s_n(oRFC4880, "rfc4880", "@"),
    ARGPARSE_s_n(oRFC4880bis, "rfc4880bis", "@"),
    ARGPARSE_s_n(oOpenPGP, "openpgp", N_("use strict OpenPGP behavior")),
    ARGPARSE_s_n(oPGP6, "pgp6", "@"), ARGPARSE_s_n(oPGP7, "pgp7", "@"),
    ARGPARSE_s_n(oPGP8, "pgp8", "@"),

    ARGPARSE_s_i(oS2KMode, "s2k-mode", "@"),
    ARGPARSE_s_s(oS2KDigest, "s2k-digest-algo", "@"),
    ARGPARSE_s_s(oS2KCipher, "s2k-cipher-algo", "@"),
    ARGPARSE_s_i(oS2KCount, "s2k-count", "@"),
    ARGPARSE_s_s(oCipherAlgo, "cipher-algo", "@"),
    ARGPARSE_s_s(oDigestAlgo, "digest-algo", "@"),
    ARGPARSE_s_s(oCertDigestAlgo, "cert-digest-algo", "@"),
    ARGPARSE_s_s(oCompressAlgo, "compress-algo", "@"),
    ARGPARSE_s_s(oCompressAlgo, "compression-algo", "@"), /* Alias */
    ARGPARSE_s_n(oThrowKeyids, "throw-keyids", "@"),
    ARGPARSE_s_n(oNoThrowKeyids, "no-throw-keyids", "@"),
    ARGPARSE_s_s(oSetNotation, "set-notation", "@"),
    ARGPARSE_s_s(oSigNotation, "sig-notation", "@"),
    ARGPARSE_s_s(oCertNotation, "cert-notation", "@"),

    ARGPARSE_group(302, N_("@\n(See the man page for a complete listing of all "
                           "commands and options)\n")),

    ARGPARSE_group(
        303, N_("@\nExamples:\n\n"
                " -se -r Bob [file]          sign and encrypt for user Bob\n"
                " --clear-sign [file]        make a clear text signature\n"
                " --detach-sign [file]       make a detached signature\n"
                " --list-keys [names]        show keys\n"
                " --fingerprint [names]      show fingerprints\n")),

/* More hidden commands and options. */
#ifndef NO_TRUST_MODELS
    ARGPARSE_c(aListTrustDB, "list-trustdb", "@"),
#endif

    /* Not yet used:
       ARGPARSE_c (aListTrustPath, "list-trust-path", "@"), */
    ARGPARSE_c(aDeleteSecretAndPublicKeys, "delete-secret-and-public-keys",
               "@"),

    ARGPARSE_s_s(oPassphrase, "passphrase", "@"),
    ARGPARSE_s_i(oPassphraseFD, "passphrase-fd", "@"),
    ARGPARSE_s_s(oPassphraseFile, "passphrase-file", "@"),
    ARGPARSE_s_i(oCommandFD, "command-fd", "@"),
    ARGPARSE_s_s(oCommandFile, "command-file", "@"),
    ARGPARSE_s_n(oNoVerbose, "no-verbose", "@"),

#ifndef NO_TRUST_MODELS
    ARGPARSE_s_s(oTrustDBName, "trustdb-name", "@"),
    ARGPARSE_s_n(oAutoCheckTrustDB, "auto-check-trustdb", "@"),
    ARGPARSE_s_n(oNoAutoCheckTrustDB, "no-auto-check-trustdb", "@"),
    ARGPARSE_s_s(oForceOwnertrust, "force-ownertrust", "@"),
#endif

    ARGPARSE_s_n(oNoSecmemWarn, "no-secmem-warning", "@"),
    ARGPARSE_s_n(oRequireSecmem, "require-secmem", "@"),
    ARGPARSE_s_n(oNoRequireSecmem, "no-require-secmem", "@"),
    ARGPARSE_s_n(oNoPermissionWarn, "no-permission-warning", "@"),
    ARGPARSE_s_n(oNoArmor, "no-armor", "@"),
    ARGPARSE_s_n(oNoDefKeyring, "no-default-keyring", "@"),
    ARGPARSE_s_n(oNoKeyring, "no-keyring", "@"),
    ARGPARSE_s_n(oNoOptions, "no-options", "@"),
    ARGPARSE_s_s(oHomedir, "homedir", "@"),
    ARGPARSE_s_n(oNoBatch, "no-batch", "@"),
    ARGPARSE_s_n(oWithColons, "with-colons", "@"),
    ARGPARSE_s_n(oWithKeyData, "with-key-data", "@"),
    ARGPARSE_s_n(oWithSigList, "with-sig-list", "@"),
    ARGPARSE_s_n(oWithSigCheck, "with-sig-check", "@"),
    ARGPARSE_c(aListKeys, "list-key", "@"),   /* alias */
    ARGPARSE_c(aListSigs, "list-sig", "@"),   /* alias */
    ARGPARSE_c(aCheckKeys, "check-sig", "@"), /* alias */
    ARGPARSE_s_n(oSkipVerify, "skip-verify", "@"),
    ARGPARSE_s_n(oSkipHiddenRecipients, "skip-hidden-recipients", "@"),
    ARGPARSE_s_n(oNoSkipHiddenRecipients, "no-skip-hidden-recipients", "@"),
    ARGPARSE_s_i(oDefCertLevel, "default-cert-check-level", "@"), /* old */
    ARGPARSE_s_s(oTrustModel, "trust-model", "@"),
    ARGPARSE_s_s(oSetFilename, "set-filename", "@"),
    ARGPARSE_s_s(oSetPolicyURL, "set-policy-url", "@"),
    ARGPARSE_s_s(oSigPolicyURL, "sig-policy-url", "@"),
    ARGPARSE_s_s(oCertPolicyURL, "cert-policy-url", "@"),
    ARGPARSE_s_s(oSigKeyserverURL, "sig-keyserver-url", "@"),
    ARGPARSE_s_s(oComment, "comment", "@"),
    ARGPARSE_s_n(oDefaultComment, "default-comment", "@"),
    ARGPARSE_s_n(oNoComments, "no-comments", "@"),
    ARGPARSE_s_i(oLoggerFD, "logger-fd", "@"),
    ARGPARSE_s_s(oLoggerFile, "log-file", "@"),
    ARGPARSE_s_s(oLoggerFile, "logger-file", "@"), /* 1.4 compatibility.  */
    ARGPARSE_s_n(oUtf8Strings, "utf8-strings", "@"),
    ARGPARSE_s_n(oNoUtf8Strings, "no-utf8-strings", "@"),
    ARGPARSE_s_n(oWithFingerprint, "with-fingerprint", "@"),
    ARGPARSE_s_n(oWithSubkeyFingerprint, "with-subkey-fingerprint", "@"),
    ARGPARSE_s_n(oWithSubkeyFingerprint, "with-subkey-fingerprints", "@"),
    ARGPARSE_s_n(oWithICAOSpelling, "with-icao-spelling", "@"),
    ARGPARSE_s_n(oWithKeygrip, "with-keygrip", "@"),
    ARGPARSE_s_n(oWithSecret, "with-secret", "@"),
    ARGPARSE_s_n(oWithWKDHash, "with-wkd-hash", "@"),
    ARGPARSE_s_s(oDisableCipherAlgo, "disable-cipher-algo", "@"),
    ARGPARSE_s_s(oDisablePubkeyAlgo, "disable-pubkey-algo", "@"),
    ARGPARSE_s_n(oAllowFreeformUID, "allow-freeform-uid", "@"),
    ARGPARSE_s_n(oNoAllowFreeformUID, "no-allow-freeform-uid", "@"),
    ARGPARSE_s_n(oListOnly, "list-only", "@"),
    ARGPARSE_s_n(oPrintDANERecords, "print-dane-records", "@"),
    ARGPARSE_s_n(oIgnoreTimeConflict, "ignore-time-conflict", "@"),
    ARGPARSE_s_n(oIgnoreValidFrom, "ignore-valid-from", "@"),
    ARGPARSE_s_n(oIgnoreCrcError, "ignore-crc-error", "@"),
    ARGPARSE_s_n(oShowSessionKey, "show-session-key", "@"),
    ARGPARSE_s_s(oOverrideSessionKey, "override-session-key", "@"),
    ARGPARSE_s_i(oOverrideSessionKeyFD, "override-session-key-fd", "@"),
    ARGPARSE_s_n(oAutoKeyRetrieve, "auto-key-retrieve", "@"),
    ARGPARSE_s_n(oNoAutoKeyRetrieve, "no-auto-key-retrieve", "@"),
    ARGPARSE_s_n(oNoSigCache, "no-sig-cache", "@"),
    ARGPARSE_s_n(oMergeOnly, "merge-only", "@"),
    ARGPARSE_s_n(oTryAllSecrets, "try-all-secrets", "@"),
    ARGPARSE_s_n(oPreservePermissions, "preserve-permissions", "@"),
    ARGPARSE_s_s(oDefaultPreferenceList, "default-preference-list", "@"),
    ARGPARSE_s_s(oDefaultKeyserverURL, "default-keyserver-url", "@"),
    ARGPARSE_s_s(oPersonalCipherPreferences, "personal-cipher-preferences",
                 "@"),
    ARGPARSE_s_s(oPersonalDigestPreferences, "personal-digest-preferences",
                 "@"),
    ARGPARSE_s_s(oPersonalCompressPreferences, "personal-compress-preferences",
                 "@"),
    ARGPARSE_s_s(oFakedSystemTime, "faked-system-time", "@"),
    ARGPARSE_s_s(oWeakDigest, "weak-digest", "@"),
    ARGPARSE_s_n(oUnwrap, "unwrap", "@"),
    ARGPARSE_s_n(oOnlySignTextIDs, "only-sign-text-ids", "@"),

    /* Aliases.  I constantly mistype these, and assume other people do
       as well. */
    ARGPARSE_s_s(oPersonalCipherPreferences, "personal-cipher-prefs", "@"),
    ARGPARSE_s_s(oPersonalDigestPreferences, "personal-digest-prefs", "@"),
    ARGPARSE_s_s(oPersonalCompressPreferences, "personal-compress-prefs", "@"),

    ARGPARSE_s_s(oLCctype, "lc-ctype", "@"),
    ARGPARSE_s_s(oLCmessages, "lc-messages", "@"),
    ARGPARSE_s_s(oGroup, "group", "@"), ARGPARSE_s_s(oUnGroup, "ungroup", "@"),
    ARGPARSE_s_n(oNoGroups, "no-groups", "@"),
    ARGPARSE_s_n(oEnableProgressFilter, "enable-progress-filter", "@"),
    ARGPARSE_s_n(oMultifile, "multifile", "@"),
    ARGPARSE_s_s(oKeyidFormat, "keyid-format", "@"),
    ARGPARSE_s_n(oExitOnStatusWriteError, "exit-on-status-write-error", "@"),
    ARGPARSE_s_i(oLimitCardInsertTries, "limit-card-insert-tries", "@"),

    ARGPARSE_s_n(oEnableLargeRSA, "enable-large-rsa", "@"),
    ARGPARSE_s_n(oDisableLargeRSA, "disable-large-rsa", "@"),
    ARGPARSE_s_n(oEnableDSA2, "enable-dsa2", "@"),
    ARGPARSE_s_n(oDisableDSA2, "disable-dsa2", "@"),

    ARGPARSE_s_s(oDefaultNewKeyAlgo, "default-new-key-algo", "@"),

    /* These two are aliases to help users of the PGP command line
       product use gpg with minimal pain.  Many commands are common
       already as they seem to have borrowed commands from us.  Now I'm
       returning the favor. */
    ARGPARSE_s_s(oLocalUser, "sign-with", "@"),
    ARGPARSE_s_s(oRecipient, "user", "@"),

    ARGPARSE_s_n(oRequireCrossCert, "require-backsigs", "@"),
    ARGPARSE_s_n(oRequireCrossCert, "require-cross-certification", "@"),
    ARGPARSE_s_n(oNoRequireCrossCert, "no-require-backsigs", "@"),
    ARGPARSE_s_n(oNoRequireCrossCert, "no-require-cross-certification", "@"),

    /* New options.  Fixme: Should go more to the top.  */
    ARGPARSE_s_s(oAutoKeyLocate, "auto-key-locate", "@"),
    ARGPARSE_s_n(oNoAutoKeyLocate, "no-auto-key-locate", "@"),

    ARGPARSE_end()};

/* The list of supported debug flags.  */
const static struct debug_flags_s debug_flags[] = {
    {DBG_PACKET_VALUE, "packet"},
    {DBG_MPI_VALUE, "mpi"},
    {DBG_CRYPTO_VALUE, "crypto"},
    {DBG_FILTER_VALUE, "filter"},
    {DBG_IOBUF_VALUE, "iobuf"},
    {DBG_MEMORY_VALUE, "memory"},
    {DBG_CACHE_VALUE, "cache"},
    {DBG_MEMSTAT_VALUE, "memstat"},
    {DBG_TRUST_VALUE, "trust"},
    {DBG_HASHING_VALUE, "hashing"},
    {DBG_IPC_VALUE, "ipc"},
    {DBG_CLOCK_VALUE, "clock"},
    {DBG_LOOKUP_VALUE, "lookup"},
    {DBG_EXTPROG_VALUE, "extprog"},
    {0, NULL}};

int g10_errors_seen = 0;

static char *build_list(const std::string &text, char letter,
                        const char *(*mapf)(int), int (*chkf)(int));
static void set_cmd(enum cmd_and_opt_values *ret_cmd,
                    enum cmd_and_opt_values new_cmd);
static void print_mds(const char *fname, int algo);
static void add_notation_data(const char *string, int which, bool utf8_strings);
static void add_policy_url(const char *string, int which);
static void add_keyserver_url(const char *string, int which);
static void read_sessionkey_from_fd(int fd);

static int build_list_pk_test_algo(int algo) {
  /* Show only one "RSA" string.  If RSA_E or RSA_S is available RSA
     is also available.  */
  if (algo == PUBKEY_ALGO_RSA_E || algo == PUBKEY_ALGO_RSA_S)
    return GPG_ERR_DIGEST_ALGO;

  return openpgp_pk_test_algo((pubkey_algo_t)(algo));
}

static const char *build_list_pk_algo_name(int algo) {
  return openpgp_pk_algo_name((pubkey_algo_t)(algo));
}

static int build_list_cipher_test_algo(int algo) {
  return openpgp_cipher_test_algo((cipher_algo_t)(algo));
}

static const char *build_list_cipher_algo_name(int algo) {
  return openpgp_cipher_algo_name((cipher_algo_t)(algo));
}

static int build_list_md_test_algo(int algo) {
  /* By default we do not accept MD5 based signatures.  To avoid
     confusion we do not announce support for it either.  */
  if (algo == DIGEST_ALGO_MD5) return GPG_ERR_DIGEST_ALGO;

  return openpgp_md_test_algo((digest_algo_t)(algo));
}

static const char *build_list_md_algo_name(int algo) {
  return openpgp_md_algo_name(algo);
}

static const char *my_strusage(int level) {
  static char *digests, *pubkeys, *ciphers, *zips, *ver_gcry;
  const char *p = NULL;

  switch (level) {
    case 11:
      p = "@GPG@ (@GNUPG@)";
      break;
    case 13:
      p = VERSION;
      break;
    case 19:
      p = _("Please report bugs to <@EMAIL@>.\n");
      break;

    case 20:
      break;

    case 1:
    case 40:
      p = _("Usage: @GPG@ [options] [files] (-h for help)");
      break;
    case 41:
      p =
          _("Syntax: @GPG@ [options] [files]\n"
            "Sign, check, encrypt or decrypt\n"
            "Default operation depends on the input data\n");
      break;

    case 31:
      p = "\nHome: ";
      break;
    case 32:
      p = gnupg_homedir();
      break;
    case 33:
      p = _("\nSupported algorithms:\n");
      break;
    case 34:
      if (!pubkeys)
        pubkeys = build_list(_("Pubkey: "), 1, build_list_pk_algo_name,
                             build_list_pk_test_algo);
      p = pubkeys;
      break;
    case 35:
      if (!ciphers)
        ciphers = build_list(_("Cipher: "), 'S', build_list_cipher_algo_name,
                             build_list_cipher_test_algo);
      p = ciphers;
      break;
    case 36:
      if (!digests)
        digests = build_list(_("Hash: "), 'H', build_list_md_algo_name,
                             build_list_md_test_algo);
      p = digests;
      break;
    case 37:
      if (!zips)
        zips = build_list(_("Compression: "), 'Z', compress_algo_to_string,
                          check_compress_algo);
      p = zips;
      break;

    default:
      p = NULL;
  }
  return p;
}

static char *build_list(const std::string &prefix, char letter,
                        const char *(*mapf)(int), int (*chkf)(int)) {
  std::vector<std::string> list;
  int i;
  const char *s;

  for (i = 0; i <= 110; i++)
    if (!chkf(i) && (s = mapf(i))) {
      if (opt.verbose && letter) {
        std::stringstream fmt;
        if (letter == 1)
          fmt << s << " (" << i << ")";
        else
          fmt << s << " (" << letter << i << ")";
        list.emplace_back(fmt.str());
      } else
        list.emplace_back(s);
    }

  std::string out = prefix + boost::algorithm::join(list, ", ") + "\n";
  char *result = (char *)xmalloc(out.size() + 1);
  strcpy(result, out.data());
  return result;
}

static void wrong_args(const char *text) {
  es_fprintf(es_stderr, _("usage: %s [options] %s\n"), GPG_NAME, text);
  g10_exit(2);
}

/* Setup the debugging.  With a LEVEL of NULL only the active debug
   flags are propagated to the subsystems.  With LEVEL set, a specific
   set of debug flags is set; thus overriding all flags already
   set. */
static void set_debug(const char *level) {
  int numok = (level && digitp(level));
  int numlvl = numok ? atoi(level) : 0;

  if (!level)
    ;
  else if (!strcmp(level, "none") || (numok && numlvl < 1))
    opt.debug = 0;
  else if (!strcmp(level, "basic") || (numok && numlvl <= 2))
    opt.debug = DBG_MEMSTAT_VALUE;
  else if (!strcmp(level, "advanced") || (numok && numlvl <= 5))
    opt.debug = DBG_MEMSTAT_VALUE | DBG_TRUST_VALUE | DBG_EXTPROG_VALUE;
  else if (!strcmp(level, "expert") || (numok && numlvl <= 8))
    opt.debug =
        (DBG_MEMSTAT_VALUE | DBG_TRUST_VALUE | DBG_EXTPROG_VALUE |
         DBG_CACHE_VALUE | DBG_LOOKUP | DBG_FILTER_VALUE | DBG_PACKET_VALUE);
  else if (!strcmp(level, "guru") || numok) {
    opt.debug = ~0;
    /* Unless the "guru" string has been used we don't want to allow
       hashing debugging.  The rationale is that people tend to
       select the highest debug value and would then clutter their
       disk with debug files which may reveal confidential data.  */
    if (numok) opt.debug &= ~(DBG_HASHING_VALUE);
  } else {
    log_error(_("invalid debug-level '%s' given\n"), level);
    g10_exit(2);
  }

  if ((opt.debug & DBG_MEMORY_VALUE)) memory_debug_mode = 1;
  if ((opt.debug & DBG_MEMSTAT_VALUE)) memory_stat_debug_mode = 1;
  if (DBG_MPI) gcry_control(GCRYCTL_SET_DEBUG_FLAGS, 2);
  if (DBG_CRYPTO) gcry_control(GCRYCTL_SET_DEBUG_FLAGS, 1);
  if ((opt.debug & DBG_IOBUF_VALUE)) iobuf_debug_mode = 1;
  gcry_control(GCRYCTL_SET_VERBOSITY, (int)opt.verbose);

  if (opt.debug) parse_debug_flag(NULL, &opt.debug, debug_flags);
}

/* We set the screen dimensions for UI purposes.  Do not allow screens
   smaller than 80x24 for the sake of simplicity. */
static void set_screen_dimensions(void) {
#ifndef HAVE_W32_SYSTEM
  char *str;

  str = getenv("COLUMNS");
  if (str) opt.screen_columns = atoi(str);

  str = getenv("LINES");
  if (str) opt.screen_lines = atoi(str);
#endif

  if (opt.screen_columns < 80 || opt.screen_columns > 255)
    opt.screen_columns = 80;

  if (opt.screen_lines < 24 || opt.screen_lines > 255) opt.screen_lines = 24;
}

/* Helper to open a file FNAME either for reading or writing to be
   used with --status-file etc functions.  Not generally useful but it
   avoids the riscos specific functions and well some Windows people
   might like it too.  Prints an error message and returns -1 on
   error.  On success the file descriptor is returned.  */
static int open_info_file(const char *fname, int for_write, int binary) {
#if defined(ENABLE_SELINUX_HACKS)
  /* We can't allow these even when testing for a secured filename
     because files to be secured might not yet been secured.  This is
     similar to the option file but in that case it is unlikely that
     sensitive information may be retrieved by means of error
     messages.  */
  (void)fname;
  (void)for_write;
  (void)binary;
  return -1;
#else
  int fd;

  if (binary) binary = MY_O_BINARY;

  /*   if (is_secured_filename (fname)) */
  /*     { */
  /*       fd = -1; */
  /*       gpg_err_set_errno (EPERM); */
  /*     } */
  /*   else */
  /*     { */
  do {
    if (for_write)
      fd = open(fname, O_CREAT | O_TRUNC | O_WRONLY | binary,
                S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
    else
      fd = open(fname, O_RDONLY | binary);
  } while (fd == -1 && errno == EINTR);
  /*     } */
  if (fd == -1)
    log_error(
        for_write ? _("can't create '%s': %s\n") : _("can't open '%s': %s\n"),
        fname, strerror(errno));

  return fd;
#endif
}

static void set_cmd(enum cmd_and_opt_values *ret_cmd,
                    enum cmd_and_opt_values new_cmd) {
  enum cmd_and_opt_values cmd = *ret_cmd;

  if (!cmd || cmd == new_cmd)
    cmd = new_cmd;
  else if (cmd == aSign && new_cmd == aEncr)
    cmd = aSignEncr;
  else if (cmd == aEncr && new_cmd == aSign)
    cmd = aSignEncr;
  else if (cmd == aSign && new_cmd == aSym)
    cmd = aSignSym;
  else if (cmd == aSym && new_cmd == aSign)
    cmd = aSignSym;
  else if (cmd == aSym && new_cmd == aEncr)
    cmd = aEncrSym;
  else if (cmd == aEncr && new_cmd == aSym)
    cmd = aEncrSym;
  else if (cmd == aSignEncr && new_cmd == aSym)
    cmd = aSignEncrSym;
  else if (cmd == aSignSym && new_cmd == aEncr)
    cmd = aSignEncrSym;
  else if (cmd == aEncrSym && new_cmd == aSign)
    cmd = aSignEncrSym;
  else if ((cmd == aSign && new_cmd == aClearsign) ||
           (cmd == aClearsign && new_cmd == aSign))
    cmd = aClearsign;
  else {
    log_error(_("conflicting commands\n"));
    g10_exit(2);
  }

  *ret_cmd = cmd;
}

static void add_group(char *string, bool utf8_strings) {
  char *name, *value;
  auto item = opt.grouplist.begin();

  /* Break off the group name */
  name = gpg_strsep(&string, "=");
  if (string == NULL) {
    log_error(_("no = sign found in group definition '%s'\n"), name);
    return;
  }

  trim_trailing_ws((unsigned char *)(name), strlen(name));

  /* Does this group already exist? */
  while (item != opt.grouplist.end() &&
         strcasecmp(item->name.c_str(), name) != 0)
    item++;
  if (item == opt.grouplist.end()) {
    opt.grouplist.emplace_back();
    item = std::prev(opt.grouplist.end());
    item->name = name;
  }

  /* Break apart the values */
  while ((value = gpg_strsep(&string, " \t"))) {
    if (*value) item->values.emplace_back(str_to_utf8(value, utf8_strings));
  }
}

static void rm_group(char *name) {
  auto item = opt.grouplist.begin();

  trim_trailing_ws((unsigned char *)(name), strlen(name));

  while (item != opt.grouplist.end() &&
         strcasecmp(item->name.c_str(), name) != 0)
    item++;
  if (item != opt.grouplist.end()) opt.grouplist.erase(item);
}

/* We need to check three things.

   0) The homedir.  It must be x00, a directory, and owned by the
   user.

   1) The options/gpg.conf file.  Okay unless it or its containing
   directory is group or other writable or not owned by us.  Disable
   exec in this case.

   2) Extensions.  Same as #1.

   Returns true if the item is unsafe. */
static int check_permissions(const char *path, int item) {
#if defined(HAVE_STAT) && !defined(HAVE_DOSISH_SYSTEM)
  static int homedir_cache = -1;
  char *tmppath, *dir;
  struct stat statbuf, dirbuf;
  int homedir = 0, ret = 0, checkonly = 0;
  int perm = 0, own = 0, enc_dir_perm = 0, enc_dir_own = 0;

  if (opt.no_perm_warn) return 0;

  log_assert(item == 0 || item == 1 || item == 2);

  /* extensions may attach a path */
  if (item == 2 && path[0] != DIRSEP_C) {
    if (strchr(path, DIRSEP_C))
      tmppath = make_filename(path, NULL);
    else
      tmppath = make_filename(gnupg_libdir(), path, NULL);
  } else
    tmppath = xstrdup(path);

  /* If the item is located in the homedir, but isn't the homedir,
     don't continue if we already checked the homedir itself.  This is
     to avoid user confusion with an extra options file warning which
     could be rectified if the homedir itself had proper
     permissions. */
  if (item != 0 && homedir_cache > -1 &&
      !ascii_strncasecmp(gnupg_homedir(), tmppath, strlen(gnupg_homedir()))) {
    ret = homedir_cache;
    goto end;
  }

  /* It's okay if the file or directory doesn't exist */
  if (stat(tmppath, &statbuf) != 0) {
    ret = 0;
    goto end;
  }

  /* Now check the enclosing directory.  Theoretically, we could walk
     this test up to the root directory /, but for the sake of sanity,
     I'm stopping at one level down. */
  dir = make_dirname(tmppath);

  if (stat(dir, &dirbuf) != 0 || !S_ISDIR(dirbuf.st_mode)) {
    /* Weird error */
    ret = 1;
    goto end;
  }

  xfree(dir);

  /* Assume failure */
  ret = 1;

  if (item == 0) {
    /* The homedir must be x00, a directory, and owned by the user. */

    if (S_ISDIR(statbuf.st_mode)) {
      if (statbuf.st_uid == getuid()) {
        if ((statbuf.st_mode & (S_IRWXG | S_IRWXO)) == 0)
          ret = 0;
        else
          perm = 1;
      } else
        own = 1;

      homedir_cache = ret;
    }
  } else if (item == 1 || item == 2) {
    /* The options or extension file.  Okay unless it or its
       containing directory is group or other writable or not owned
       by us or root. */

    if (S_ISREG(statbuf.st_mode)) {
      if (statbuf.st_uid == getuid() || statbuf.st_uid == 0) {
        if ((statbuf.st_mode & (S_IWGRP | S_IWOTH)) == 0) {
          /* it's not writable, so make sure the enclosing
             directory is also not writable */
          if (dirbuf.st_uid == getuid() || dirbuf.st_uid == 0) {
            if ((dirbuf.st_mode & (S_IWGRP | S_IWOTH)) == 0)
              ret = 0;
            else
              enc_dir_perm = 1;
          } else
            enc_dir_own = 1;
        } else {
          /* it's writable, so the enclosing directory had
             better not let people get to it. */
          if (dirbuf.st_uid == getuid() || dirbuf.st_uid == 0) {
            if ((dirbuf.st_mode & (S_IRWXG | S_IRWXO)) == 0)
              ret = 0;
            else
              perm = enc_dir_perm = 1; /* unclear which one to fix! */
          } else
            enc_dir_own = 1;
        }
      } else
        own = 1;
    }
  } else
    BUG();

  if (!checkonly) {
    if (own) {
      if (item == 0)
        log_info(_("WARNING: unsafe ownership on"
                   " homedir '%s'\n"),
                 tmppath);
      else if (item == 1)
        log_info(_("WARNING: unsafe ownership on"
                   " configuration file '%s'\n"),
                 tmppath);
      else
        log_info(_("WARNING: unsafe ownership on"
                   " extension '%s'\n"),
                 tmppath);
    }
    if (perm) {
      if (item == 0)
        log_info(_("WARNING: unsafe permissions on"
                   " homedir '%s'\n"),
                 tmppath);
      else if (item == 1)
        log_info(_("WARNING: unsafe permissions on"
                   " configuration file '%s'\n"),
                 tmppath);
      else
        log_info(_("WARNING: unsafe permissions on"
                   " extension '%s'\n"),
                 tmppath);
    }
    if (enc_dir_own) {
      if (item == 0)
        log_info(_("WARNING: unsafe enclosing directory ownership on"
                   " homedir '%s'\n"),
                 tmppath);
      else if (item == 1)
        log_info(_("WARNING: unsafe enclosing directory ownership on"
                   " configuration file '%s'\n"),
                 tmppath);
      else
        log_info(_("WARNING: unsafe enclosing directory ownership on"
                   " extension '%s'\n"),
                 tmppath);
    }
    if (enc_dir_perm) {
      if (item == 0)
        log_info(_("WARNING: unsafe enclosing directory permissions on"
                   " homedir '%s'\n"),
                 tmppath);
      else if (item == 1)
        log_info(_("WARNING: unsafe enclosing directory permissions on"
                   " configuration file '%s'\n"),
                 tmppath);
      else
        log_info(_("WARNING: unsafe enclosing directory permissions on"
                   " extension '%s'\n"),
                 tmppath);
    }
  }

end:
  xfree(tmppath);

  if (homedir) homedir_cache = ret;

  return ret;

#else /*!(HAVE_STAT && !HAVE_DOSISH_SYSTEM)*/
  (void)path;
  (void)item;
  return 0;
#endif /*!(HAVE_STAT && !HAVE_DOSISH_SYSTEM)*/
}

/* Print the OpenPGP defined algo numbers.  */
static void print_algo_numbers(int (*checker)(int)) {
  int i, first = 1;

  for (i = 0; i <= 110; i++) {
    if (!checker(i)) {
      if (first)
        first = 0;
      else
        es_printf(";");
      es_printf("%d", i);
    }
  }
}

static void print_algo_names(int (*checker)(int), const char *(*mapper)(int)) {
  int i, first = 1;

  for (i = 0; i <= 110; i++) {
    if (!checker(i)) {
      if (first)
        first = 0;
      else
        es_printf(";");
      es_printf("%s", mapper(i));
    }
  }
}

static int parse_subpacket_list(char *list) {
  char *tok;
  byte subpackets[128], i;
  int count = 0;

  if (!list) {
    /* No arguments means all subpackets */
    memset(subpackets + 1, 1, sizeof(subpackets) - 1);
    count = 127;
  } else {
    memset(subpackets, 0, sizeof(subpackets));

    /* Merge with earlier copy */
    if (opt.show_subpackets) {
      byte *in;

      for (in = opt.show_subpackets; *in; in++) {
        if (*in > 127 || *in < 1) BUG();

        if (!subpackets[*in]) count++;
        subpackets[*in] = 1;
      }
    }

    while ((tok = gpg_strsep(&list, " ,"))) {
      if (!*tok) continue;

      i = atoi(tok);
      if (i > 127 || i < 1) return 0;

      if (!subpackets[i]) count++;
      subpackets[i] = 1;
    }
  }

  xfree(opt.show_subpackets);
  opt.show_subpackets = (byte *)xmalloc(count + 1);
  opt.show_subpackets[count--] = 0;

  for (i = 1; i < 128 && count >= 0; i++)
    if (subpackets[i]) opt.show_subpackets[count--] = i;

  return 1;
}

static int parse_list_options(char *str) {
  const char *subpackets = ""; /* something that isn't NULL */
  struct parse_options lopts[] = {
      {"show-usage", LIST_SHOW_USAGE, NULL,
       N_("show key usage information during key listings")},
      {"show-policy-urls", LIST_SHOW_POLICY_URLS, NULL,
       N_("show policy URLs during signature listings")},
      {"show-notations", LIST_SHOW_NOTATIONS, NULL,
       N_("show all notations during signature listings")},
      {"show-std-notations", LIST_SHOW_STD_NOTATIONS, NULL,
       N_("show IETF standard notations during signature listings")},
      {"show-standard-notations", LIST_SHOW_STD_NOTATIONS, NULL, NULL},
      {"show-user-notations", LIST_SHOW_USER_NOTATIONS, NULL,
       N_("show user-supplied notations during signature listings")},
      {"show-keyserver-urls", LIST_SHOW_KEYSERVER_URLS, NULL,
       N_("show preferred keyserver URLs during signature listings")},
      {"show-uid-validity", LIST_SHOW_UID_VALIDITY, NULL,
       N_("show user ID validity during key listings")},
      {"show-unusable-uids", LIST_SHOW_UNUSABLE_UIDS, NULL,
       N_("show revoked and expired user IDs in key listings")},
      {"show-unusable-subkeys", LIST_SHOW_UNUSABLE_SUBKEYS, NULL,
       N_("show revoked and expired subkeys in key listings")},
      {"show-keyring", LIST_SHOW_KEYRING, NULL,
       N_("show the keyring name in key listings")},
      {"show-sig-expire", LIST_SHOW_SIG_EXPIRE, NULL,
       N_("show expiration dates during signature listings")},
      {"show-sig-subpackets", LIST_SHOW_SIG_SUBPACKETS, (char **)&subpackets,
       NULL},
      {NULL, 0, NULL, NULL}};

  if (parse_options(str, &opt.list_options, lopts, 1)) {
    if (opt.list_options & LIST_SHOW_SIG_SUBPACKETS) {
      /* Unset so users can pass multiple lists in. */
      opt.list_options &= ~LIST_SHOW_SIG_SUBPACKETS;
      if (!parse_subpacket_list((char *)(subpackets))) return 0;
    } else if (subpackets == NULL && opt.show_subpackets) {
      /* User did 'no-show-subpackets' */
      xfree(opt.show_subpackets);
      opt.show_subpackets = NULL;
    }

    return 1;
  } else
    return 0;
}

/* Collapses argc/argv into a single string that must be freed */
static char *collapse_args(int argc, char *argv[]) {
  char *str = NULL;
  int i, first = 1, len = 0;

  for (i = 0; i < argc; i++) {
    len += strlen(argv[i]) + 2;
    str = (char *)xrealloc(str, len);
    if (first) {
      str[0] = '\0';
      first = 0;
    } else
      strcat(str, " ");

    strcat(str, argv[i]);
  }

  return str;
}

#ifndef NO_TRUST_MODELS
static void parse_trust_model(const char *model) {
  if (ascii_strcasecmp(model, "pgp") == 0)
    opt.trust_model = TM_PGP;
  else if (ascii_strcasecmp(model, "classic") == 0)
    opt.trust_model = TM_CLASSIC;
  else if (ascii_strcasecmp(model, "always") == 0)
    opt.trust_model = TM_ALWAYS;
  else if (ascii_strcasecmp(model, "direct") == 0)
    opt.trust_model = TM_DIRECT;
  else if (ascii_strcasecmp(model, "auto") == 0)
    opt.trust_model = TM_AUTO;
  else
    log_error("unknown trust model '%s'\n", model);
}
#endif /*NO_TRUST_MODELS*/

static struct gnupg_compliance_option compliance_options[] = {
    {"gnupg", oGnuPG},     {"openpgp", oOpenPGP}, {"rfc4880bis", oRFC4880bis},
    {"rfc4880", oRFC4880}, {"pgp6", oPGP6},       {"pgp7", oPGP7},
    {"pgp8", oPGP8},       {"de-vs", oDE_VS}};

/* Helper to set compliance related options.  This is a separate
 * function so that it can also be used by the --compliance option
 * parser.  */
static void set_compliance_option(enum cmd_and_opt_values option) {
  switch (option) {
    case oRFC4880bis:
      opt.flags.rfc4880bis = true;
    /* fall through.  */
    case oOpenPGP:
    case oRFC4880:
      /* This is effectively the same as RFC2440, but with
         "--enable-dsa2
         --require-cross-certification". */
      opt.compliance = CO_RFC4880;
      opt.flags.dsa2 = true;
      opt.flags.require_cross_cert = true;
      opt.allow_freeform_uid = true;
      opt.def_cipher_algo = 0;
      opt.def_digest_algo = 0;
      opt.cert_digest_algo = 0;
      opt.compress_algo = -1;
      opt.s2k_mode = 3; /* iterated+salted */
      opt.s2k_digest_algo = DIGEST_ALGO_SHA1;
      opt.s2k_cipher_algo = CIPHER_ALGO_3DES;
      break;
    case oPGP6:
      opt.compliance = CO_PGP6;
      break;
    case oPGP7:
      opt.compliance = CO_PGP7;
      break;
    case oPGP8:
      opt.compliance = CO_PGP8;
      break;
    case oGnuPG:
      opt.compliance = CO_GNUPG;
      break;

    case oDE_VS:
      set_compliance_option(oOpenPGP);
      opt.compliance = CO_DE_VS;
      /* Fixme: Change other options.  */
      break;

    default:
      BUG();
  }
}

/* This function called to initialized a new control object.  It is
   assumed that this object has been zeroed out before calling this
   function. */
static void gpg_init_default_ctrl(ctrl_t ctrl) {
  ctrl->magic = SERVER_CONTROL_MAGIC;
}

/* This function is called to deinitialize a control object.  It is
   not deallocated. */
static void gpg_deinit_default_ctrl(ctrl_t ctrl) {
  gpg_dirmngr_deinit_session_data(ctrl);

  keydb_release(ctrl->cached_getkey_kdb);
}

char *get_default_configname(void) {
  char *configname = NULL;
  char *name = xstrdup(GPG_NAME EXTSEP_S "conf-" SAFE_VERSION);
  char *ver = &name[strlen(GPG_NAME EXTSEP_S "conf-")];

  do {
    if (configname) {
      char *tok;

      xfree(configname);
      configname = NULL;

      if ((tok = strrchr(ver, SAFE_VERSION_DASH)))
        *tok = '\0';
      else if ((tok = strrchr(ver, SAFE_VERSION_DOT)))
        *tok = '\0';
      else
        break;
    }

    configname = make_filename(gnupg_homedir(), name, NULL);
  } while (access(configname, R_OK));

  xfree(name);

  if (!configname)
    configname = make_filename(gnupg_homedir(), GPG_NAME EXTSEP_S "conf", NULL);
  if (!access(configname, R_OK)) {
    /* Print a warning when both config files are present.  */
    char *p = make_filename(gnupg_homedir(), "options", NULL);
    if (!access(p, R_OK))
      log_info(_("Note: old default options file '%s' ignored\n"), p);
    xfree(p);
  } else {
    /* Use the old default only if it exists.  */
    char *p = make_filename(gnupg_homedir(), "options", NULL);
    if (!access(p, R_OK)) {
      xfree(configname);
      configname = p;
    } else
      xfree(p);
  }

  return configname;
}

int gpg_main(int argc, char **argv) {
  int utf8_strings = 0;
  ARGPARSE_ARGS pargs;
  IOBUF a;
  int rc = 0;
  int orig_argc;
  char **orig_argv;
  const char *fname;
  int may_coredump;
  std::vector<std::pair<std::string, unsigned int>> remusr;
  std::vector<std::pair<std::string, unsigned int>> locusr;
  std::vector<std::pair<std::string, unsigned int>> nrings;
  armor_filter_context_t *afx = NULL;
  int detached_sig = 0;
  FILE *configfp = NULL;
  char *configname = NULL;
  char *save_configname = NULL;
  char *default_configname = NULL;
  unsigned configlineno;
  int parse_debug = 0;
  int default_config = 1;
  int default_keyring = 1;
  char *logfile = NULL;
  enum cmd_and_opt_values cmd = (cmd_and_opt_values)0;
  const char *debug_level = NULL;
#ifndef NO_TRUST_MODELS
  const char *trustdb_name = NULL;
#endif /*!NO_TRUST_MODELS*/
  char *def_cipher_string = NULL;
  char *def_digest_string = NULL;
  char *compress_algo_string = NULL;
  char *cert_digest_string = NULL;
  char *s2k_cipher_string = NULL;
  char *s2k_digest_string = NULL;
  char *pers_cipher_list = NULL;
  char *pers_digest_list = NULL;
  char *pers_compress_list = NULL;
  int multifile = 0;
  int pwfd = -1;
  int ovrseskeyfd = -1;
  int fpr_maybe_cmd = 0; /* --fingerprint maybe a command.  */
  int any_explicit_recipient = 0;
  bool require_secmem = false;
  int got_secmem = 0;
  struct assuan_malloc_hooks malloc_hooks;
  ctrl_t ctrl;

  opt = options();

  early_system_init();
  gnupg_reopen_std(GPG_NAME);
  trap_unaligned();
  gnupg_rl_initialize();
  set_strusage(my_strusage);
  gcry_control(GCRYCTL_SUSPEND_SECMEM_WARN);
  log_set_prefix(GPG_NAME, GPGRT_LOG_WITH_PREFIX);

  /* Make sure that our subsystems are ready.  */
  init_common_subsystems(&argc, &argv);

  /* Use our own logging handler for Libcgrypt.  */
  setup_libgcrypt_logging();

  /* Put random number into secure memory */
  gcry_control(GCRYCTL_USE_SECURE_RNDPOOL);

  may_coredump = disable_core_dumps();

  dotlock_create(NULL, 0); /* Register lock file cleanup. */

  /* Tell the compliance module who we are.  */
  gnupg_initialize_compliance(GNUPG_MODULE_NAME_GPG);

  /* note: if you change these lines, look at oOpenPGP */
  set_screen_dimensions();
  gnupg_set_homedir(NULL);
  additional_weak_digest("MD5");

  /* Check whether we have a config file on the command line.  */
  orig_argc = argc;
  orig_argv = argv;
  pargs.argc = &argc;
  pargs.argv = &argv;
  pargs.flags = (ARGPARSE_FLAG_KEEP | ARGPARSE_FLAG_NOVERSION);
  while (arg_parse(&pargs, opts)) {
    if (pargs.r_opt == oDebug || pargs.r_opt == oDebugAll)
      parse_debug++;
    else if (pargs.r_opt == oDebugIOLBF)
      es_setvbuf(es_stdout, NULL, _IOLBF, 0);
    else if (pargs.r_opt == oOptions) {
      /* yes there is one, so we do not try the default one, but
       * read the option file when it is encountered at the commandline
       */
      default_config = 0;
    } else if (pargs.r_opt == oNoOptions) {
      default_config = 0; /* --no-options */
    } else if (pargs.r_opt == oHomedir)
      gnupg_set_homedir(pargs.r.ret_str);
    else if (pargs.r_opt == oNoPermissionWarn)
      opt.no_perm_warn = true;
  }

#ifdef HAVE_DOSISH_SYSTEM
  if (strchr(gnupg_homedir(), '\\')) {
    char *d, *buf = xmalloc(strlen(gnupg_homedir()) + 1);
    const char *s;
    for (d = buf, s = gnupg_homedir(); *s; s++) {
      *d++ = *s == '\\' ? '/' : *s;
#ifdef HAVE_W32_SYSTEM
      if (s[1] && IsDBCSLeadByte(*s)) *d++ = *++s;
#endif
    }
    *d = 0;
    gnupg_set_homedir(buf);
  }
#endif

  /* Initialize the secure memory. */
  if (!gcry_control(GCRYCTL_INIT_SECMEM, SECMEM_BUFFER_SIZE, 0)) got_secmem = 1;

  /* malloc hooks go here ... */
  malloc_hooks.malloc = gcry_malloc;
  malloc_hooks.realloc = gcry_realloc;
  malloc_hooks.free = gcry_free;
  assuan_set_malloc_hooks(&malloc_hooks);
  setup_libassuan_logging(&opt.debug, NULL);

  /* Try for a version specific config file first */
  default_configname = get_default_configname();
  if (default_config) configname = xstrdup(default_configname);

  argc = orig_argc;
  argv = orig_argv;
  pargs.argc = &argc;
  pargs.argv = &argv;
  pargs.flags = ARGPARSE_FLAG_KEEP;

  /* By this point we have a homedir, and cannot change it. */
  check_permissions(gnupg_homedir(), 0);

next_pass:
  if (configname) {
    configlineno = 0;
    configfp = fopen(configname, "r");
    if (configfp && is_secured_file(fileno(configfp))) {
      fclose(configfp);
      configfp = NULL;
      gpg_err_set_errno(EPERM);
    }
    if (!configfp) {
      if (default_config) {
        if (parse_debug)
          log_info(_("Note: no default option file '%s'\n"), configname);
      } else {
        log_error(_("option file '%s': %s\n"), configname, strerror(errno));
        g10_exit(2);
      }
      xfree(configname);
      configname = NULL;
    }
    if (parse_debug && configname)
      log_info(_("reading options from '%s'\n"), configname);
    default_config = 0;
  }

  while (optfile_parse(configfp, configname, &configlineno, &pargs, opts)) {
    switch (pargs.r_opt) {
      case aCheckKeys:
      case aListPackets:
      case aImport:
      case aFastImport:
      case aSendKeys:
      case aRecvKeys:
      case aSearchKeys:
      case aRefreshKeys:
      case aFetchKeys:
      case aExport:
#ifdef ENABLE_CARD_SUPPORT
      case aCardStatus:
      case aCardEdit:
      case aChangePIN:
#endif /* ENABLE_CARD_SUPPORT*/
      case aListKeys:
      case aLocateKeys:
      case aListSigs:
      case aExportSecret:
      case aExportSecretSub:
      case aExportSshKey:
      case aSym:
      case aClearsign:
      case aGenRevoke:
      case aDesigRevoke:
      case aListTrustDB:
      case aCheckTrustDB:
      case aUpdateTrustDB:
      case aListTrustPath:
      case aSign:
      case aQuickSignKey:
      case aQuickLSignKey:
      case aSignKey:
      case aLSignKey:
      case aStore:
      case aQuickKeygen:
      case aQuickAddUid:
      case aQuickAddKey:
      case aQuickRevUid:
      case aQuickSetExpire:
      case aQuickSetPrimaryUid:
      case aExportOwnerTrust:
      case aImportOwnerTrust:
      case aKeygen:
      case aFullKeygen:
      case aEditKey:
      case aDeleteSecretKeys:
      case aDeleteSecretAndPublicKeys:
      case aDeleteKeys:
      case aPasswd:
        set_cmd(&cmd, (cmd_and_opt_values)(pargs.r_opt));
        break;

      case aDetachedSign:
        detached_sig = 1;
        set_cmd(&cmd, aSign);
        break;

      case aDecryptFiles:
        multifile = 1; /* fall through */
      case aDecrypt:
        set_cmd(&cmd, aDecrypt);
        break;

      case aEncrFiles:
        multifile = 1; /* fall through */
      case aEncr:
        set_cmd(&cmd, aEncr);
        break;

      case aVerifyFiles:
        multifile = 1; /* fall through */
      case aVerify:
        set_cmd(&cmd, aVerify);
        break;

      case oArmor:
        opt.armor = true;
        opt.no_armor = false;
        break;

      case oOutput:
        opt.outfile = pargs.r.ret_str;
        break;

      case oMaxOutput:
        opt.max_output = pargs.r.ret_ulong;
        break;

      case oQuiet:
        opt.quiet = true;
        break;

      case oNoTTY:
        tty_no_terminal(1);
        break;

      case oDryRun:
        opt.dry_run = true;
        break;

      case oInteractive:
        opt.interactive = true;
        break;

      case oVerbose:
        opt.verbose++;
        gcry_control(GCRYCTL_SET_VERBOSITY, (int)opt.verbose);
        opt.list_options |= LIST_SHOW_UNUSABLE_UIDS;
        opt.list_options |= LIST_SHOW_UNUSABLE_SUBKEYS;
        break;

      case oBatch:
        opt.batch = true;
        break;

      case oAnswerYes:
        opt.answer_yes = true;
        break;

      case oAnswerNo:
        opt.answer_no = true;
        break;

      case oKeyring:
        nrings.emplace_back(pargs.r.ret_str, 0);
        break;

      case oPrimaryKeyring:
        nrings.emplace_back(pargs.r.ret_str, KEYDB_RESOURCE_FLAG_PRIMARY);
        break;

      case oDebug:
        if (parse_debug_flag(pargs.r.ret_str, &opt.debug, debug_flags)) {
          pargs.r_opt = ARGPARSE_INVALID_ARG;
          pargs.err = ARGPARSE_PRINT_ERROR;
        }
        break;

      case oDebugAll:
        opt.debug = ~0;
        break;
      case oDebugLevel:
        debug_level = pargs.r.ret_str;
        break;

      case oDebugIOLBF:
        break; /* Already set in pre-parse step.  */

      case oStatusFD:
        set_status_fd(translate_sys2libc_fd_int(pargs.r.ret_int, 1));
        break;
      case oStatusFile:
        set_status_fd(open_info_file(pargs.r.ret_str, 1, 0));
        break;
      case oAttributeFD:
        set_attrib_fd(translate_sys2libc_fd_int(pargs.r.ret_int, 1));
        break;
      case oAttributeFile:
        set_attrib_fd(open_info_file(pargs.r.ret_str, 1, 1));
        break;
      case oLoggerFD:
        log_set_fd(translate_sys2libc_fd_int(pargs.r.ret_int, 1));
        break;
      case oLoggerFile:
        logfile = pargs.r.ret_str;
        break;

      case oWithFingerprint:
        opt.with_fingerprint = true;
        opt.fingerprint++;
        break;

      case oWithSubkeyFingerprint:
        opt.with_subkey_fingerprint = true;
        break;

      case oWithICAOSpelling:
        opt.with_icao_spelling = true;
        break;

      case oFingerprint:
        opt.fingerprint++;
        fpr_maybe_cmd = 1;
        break;

      case oWithKeygrip:
        opt.with_keygrip = true;
        break;

      case oWithSecret:
        opt.with_secret = true;
        break;

      case oWithWKDHash:
        opt.with_wkd_hash = true;
        break;

      case oSecretKeyring:
        /* Ignore this old option.  */
        break;

      case oOptions:
        /* config files may not be nested (silently ignore them) */
        if (!configfp) {
          xfree(configname);
          configname = xstrdup(pargs.r.ret_str);
          goto next_pass;
        }
        break;
      case oNoArmor:
        opt.no_armor = 1;
        opt.armor = 0;
        break;

      case oNoDefKeyring:
        if (default_keyring > 0) default_keyring = 0;
        break;
      case oNoKeyring:
        default_keyring = -1;
        break;

      case oNoVerbose:
        opt.verbose = 0;
        gcry_control(GCRYCTL_SET_VERBOSITY, (int)opt.verbose);
        opt.list_sigs = 0;
        break;
      case oCompletesNeeded:
        opt.completes_needed = pargs.r.ret_int;
        break;
      case oMarginalsNeeded:
        opt.marginals_needed = pargs.r.ret_int;
        break;
      case oMaxCertDepth:
        opt.max_cert_depth = pargs.r.ret_int;
        break;

#ifndef NO_TRUST_MODELS
      case oTrustDBName:
        trustdb_name = pargs.r.ret_str;
        break;

#endif /*!NO_TRUST_MODELS*/
      case oDefaultKey: {
        unsigned int fl = 0;
        fl = (pargs.r_opt << PK_LIST_SHIFT);
        if (configfp) fl |= PK_LIST_CONFIG;
        opt.def_secret_key.emplace_back(pargs.r.ret_str, fl);
      } break;
      case oDefRecipient:
        if (*pargs.r.ret_str)
          opt.def_recipient = str_to_utf8(pargs.r.ret_str, utf8_strings);
        break;
      case oDefRecipientSelf:
        opt.def_recipient = boost::none;
        opt.def_recipient_self = 1;
        break;
      case oNoDefRecipient:
        opt.def_recipient = boost::none;
        opt.def_recipient_self = 0;
        break;
      case oHomedir:
        break;

      case oNoBatch:
        opt.batch = false;
        break;

      case oWithKeyData:
        opt.with_key_data = true; /*FALLTHRU*/
      case oWithColons:
        opt.with_colons = true;
        break;

      case oWithSigCheck:
        opt.check_sigs = true; /*FALLTHRU*/
      case oWithSigList:
        opt.list_sigs = true;
        break;

      case oSkipVerify:
        opt.skip_verify = true;
        break;

      case oSkipHiddenRecipients:
        opt.skip_hidden_recipients = true;
        break;

      case oNoSkipHiddenRecipients:
        opt.skip_hidden_recipients = false;
        break;

      case aListSecretKeys:
        set_cmd(&cmd, aListSecretKeys);
        break;

#ifndef NO_TRUST_MODELS
      case oTrustModel:
        parse_trust_model(pargs.r.ret_str);
        break;
#endif /*!NO_TRUST_MODELS*/

      case oForceOwnertrust:
        log_info(_("Note: %s is not for normal use!\n"), "--force-ownertrust");
        opt.force_ownertrust = string_to_trust_value(pargs.r.ret_str);
        if (opt.force_ownertrust == -1) {
          log_error("invalid ownertrust '%s'\n", pargs.r.ret_str);
          opt.force_ownertrust = 0;
        }
        break;

      case oCompliance: {
        int compliance =
            gnupg_parse_compliance_option(pargs.r.ret_str, compliance_options,
                                          DIM(compliance_options), opt.quiet);
        if (compliance < 0) g10_exit(1);
        set_compliance_option((cmd_and_opt_values)(compliance));
      } break;
      case oOpenPGP:
      case oRFC4880:
      case oRFC4880bis:
      case oPGP6:
      case oPGP7:
      case oPGP8:
      case oGnuPG:
        set_compliance_option((cmd_and_opt_values)(pargs.r_opt));
        break;

      case oSetPolicyURL:
        add_policy_url(pargs.r.ret_str, 0);
        add_policy_url(pargs.r.ret_str, 1);
        break;
      case oSigPolicyURL:
        add_policy_url(pargs.r.ret_str, 0);
        break;
      case oCertPolicyURL:
        add_policy_url(pargs.r.ret_str, 1);
        break;
      case oSigKeyserverURL:
        add_keyserver_url(pargs.r.ret_str, 0);
        break;

      case oThrowKeyids:
        opt.throw_keyids = true;
        break;

      case oNoThrowKeyids:
        opt.throw_keyids = false;
        break;

      case oDisableSignerUID:
        opt.flags.disable_signer_uid = true;
        break;

      case oS2KMode:
        opt.s2k_mode = pargs.r.ret_int;
        break;
      case oS2KDigest:
        s2k_digest_string = xstrdup(pargs.r.ret_str);
        break;
      case oS2KCipher:
        s2k_cipher_string = xstrdup(pargs.r.ret_str);
        break;
      case oS2KCount:
        if (pargs.r.ret_int)
          opt.s2k_count = encode_s2k_iterations(pargs.r.ret_int);
        else
          opt.s2k_count = 0; /* Auto-calibrate when needed.  */
        break;

      case oRecipient:
      case oHiddenRecipient:
      case oRecipientFile:
      case oHiddenRecipientFile:
        /* Store the recipient.  Note that we also store the
         * option as private data in the flags.  This is achieved
         * by shifting the option value to the left so to keep
         * enough space for the flags.  */
        {
          unsigned int flags = 0;

          flags = (pargs.r_opt << PK_LIST_SHIFT);
          if (configfp) flags |= PK_LIST_CONFIG;
          if (pargs.r_opt == oHiddenRecipient ||
              pargs.r_opt == oHiddenRecipientFile)
            flags |= PK_LIST_HIDDEN;
          if (pargs.r_opt == oRecipientFile ||
              pargs.r_opt == oHiddenRecipientFile)
            flags |= PK_LIST_FROM_FILE;
          remusr.emplace_back(str_to_utf8(pargs.r.ret_str, utf8_strings),
                              flags);
          any_explicit_recipient = 1;
        }
        break;

      case oEncryptTo:
      case oHiddenEncryptTo:
        /* Store an additional recipient.  */
        {
          unsigned int flags = 0;

          flags = (pargs.r_opt << PK_LIST_SHIFT) | PK_LIST_ENCRYPT_TO;
          if (configfp) flags |= PK_LIST_CONFIG;
          if (pargs.r_opt == oHiddenRecipient ||
              pargs.r_opt == oHiddenEncryptTo)
            flags |= PK_LIST_HIDDEN;
          remusr.emplace_back(str_to_utf8(pargs.r.ret_str, utf8_strings),
                              flags);
        }
        break;

      case oNoEncryptTo:
        opt.no_encrypt_to = true;
        break;

      case oEncryptToDefaultKey:
        opt.encrypt_to_default_key = configfp ? 2 : 1;
        break;

      case oTrySecretKey:
        opt.secret_keys_to_try.emplace_back(
            str_to_utf8(pargs.r.ret_str, utf8_strings));
        break;

      case oMimemode:
        opt.mimemode = true;
        opt.textmode = true;
        break;

      case oTextmode:
        opt.textmode = true;
        break;

      case oNoTextmode:
        opt.textmode = false;
        opt.mimemode = false;
        break;

      case oExpert:
        opt.expert = true;
        break;

      case oNoExpert:
        opt.expert = false;
        break;

      case oDefSigExpire:
        if (*pargs.r.ret_str != '\0') {
          if (parse_expire_string(pargs.r.ret_str) == (u32)-1)
            log_error(_("'%s' is not a valid signature expiration\n"),
                      pargs.r.ret_str);
          else
            opt.def_sig_expire = pargs.r.ret_str;
        }
        break;

      case oAskSigExpire:
        opt.ask_sig_expire = true;
        break;

      case oNoAskSigExpire:
        opt.ask_sig_expire = false;
        break;

      case oDefCertExpire:
        if (*pargs.r.ret_str != '\0') {
          if (parse_expire_string(pargs.r.ret_str) == (u32)-1)
            log_error(_("'%s' is not a valid signature expiration\n"),
                      pargs.r.ret_str);
          else
            opt.def_cert_expire = pargs.r.ret_str;
        }
        break;

      case oAskCertExpire:
        opt.ask_cert_expire = true;
        break;

      case oNoAskCertExpire:
        opt.ask_cert_expire = false;
        break;

      case oDefCertLevel:
        opt.def_cert_level = pargs.r.ret_int;
        break;
      case oMinCertLevel:
        opt.min_cert_level = pargs.r.ret_int;
        break;
      case oAskCertLevel:
        opt.ask_cert_level = 1;
        break;
      case oNoAskCertLevel:
        opt.ask_cert_level = 0;
        break;

      case oLocalUser: /* store the local users */
      {
        unsigned int flags = (pargs.r_opt << PK_LIST_SHIFT);
        if (configfp) flags |= PK_LIST_CONFIG;
        locusr.emplace_back(str_to_utf8(pargs.r.ret_str, utf8_strings), flags);
      } break;

      case oSender: {
        char *mbox = mailbox_from_userid(pargs.r.ret_str);
        if (!mbox)
          log_error(_("\"%s\" is not a proper mail address\n"),
                    pargs.r.ret_str);
        else {
          opt.sender_list.emplace_back(mbox);
          xfree(mbox);
        }
      } break;
      case oPassphrase:
        set_passphrase_from_string(pargs.r.ret_str);
        break;
      case oPassphraseFD:
        pwfd = translate_sys2libc_fd_int(pargs.r.ret_int, 0);
        break;
      case oPassphraseFile:
        pwfd = open_info_file(pargs.r.ret_str, 0, 1);
        break;

      case oCommandFD:
        opt.command_fd = translate_sys2libc_fd_int(pargs.r.ret_int, 0);
        if (!gnupg_fd_valid(opt.command_fd))
          log_fatal("command-fd is invalid: %s\n", strerror(errno));
        break;
      case oCommandFile:
        opt.command_fd = open_info_file(pargs.r.ret_str, 0, 1);
        break;
      case oCipherAlgo:
        def_cipher_string = xstrdup(pargs.r.ret_str);
        break;
      case oDigestAlgo:
        def_digest_string = xstrdup(pargs.r.ret_str);
        break;
      case oCompressAlgo:
        /* If it is all digits, stick a Z in front of it for
           later.  This is for backwards compatibility with
           versions that took the compress algorithm number. */
        {
          char *pt = pargs.r.ret_str;
          while (*pt) {
            if (!isascii(*pt) || !isdigit(*pt)) break;

            pt++;
          }

          if (*pt == '\0') {
            compress_algo_string = (char *)xmalloc(strlen(pargs.r.ret_str) + 2);
            strcpy(compress_algo_string, "Z");
            strcat(compress_algo_string, pargs.r.ret_str);
          } else
            compress_algo_string = xstrdup(pargs.r.ret_str);
        }
        break;
      case oCertDigestAlgo:
        cert_digest_string = xstrdup(pargs.r.ret_str);
        break;

      case oNoSecmemWarn:
        gcry_control(GCRYCTL_DISABLE_SECMEM_WARN);
        break;

      case oRequireSecmem:
        require_secmem = true;
        break;

      case oNoRequireSecmem:
        require_secmem = false;
        break;

      case oNoPermissionWarn:
        opt.no_perm_warn = true;
        break;

      case oKeyServer: {
        keyserver_spec_t keyserver;
        keyserver = parse_keyserver_uri(pargs.r.ret_str, 0);
        if (!keyserver)
          log_error(_("could not parse keyserver URL\n"));
        else {
          /* We only support a single keyserver.  Later ones
             override earlier ones.  (Since we parse the
             config file first and then the command line
             arguments, the command line takes
             precedence.)  */
          if (opt.keyserver) free_keyserver_spec(opt.keyserver);
          opt.keyserver = keyserver;
        }
      } break;
      case oKeyServerOptions:
        if (!parse_keyserver_options(pargs.r.ret_str)) {
          if (configname)
            log_error(_("%s:%d: invalid keyserver options\n"), configname,
                      configlineno);
          else
            log_error(_("invalid keyserver options\n"));
        }
        break;
      case oImportOptions:
        if (!parse_import_options(pargs.r.ret_str, &opt.import_options, 1)) {
          if (configname)
            log_error(_("%s:%d: invalid import options\n"), configname,
                      configlineno);
          else
            log_error(_("invalid import options\n"));
        }
        break;
      case oImportFilter:
        rc = parse_and_set_import_filter(pargs.r.ret_str);
        if (rc) log_error(_("invalid filter option: %s\n"), gpg_strerror(rc));
        break;
      case oExportOptions:
        if (!parse_export_options(pargs.r.ret_str, &opt.export_options, 1)) {
          if (configname)
            log_error(_("%s:%d: invalid export options\n"), configname,
                      configlineno);
          else
            log_error(_("invalid export options\n"));
        }
        break;
      case oExportFilter:
        rc = parse_and_set_export_filter(pargs.r.ret_str);
        if (rc) log_error(_("invalid filter option: %s\n"), gpg_strerror(rc));
        break;
      case oListOptions:
        if (!parse_list_options(pargs.r.ret_str)) {
          if (configname)
            log_error(_("%s:%d: invalid list options\n"), configname,
                      configlineno);
          else
            log_error(_("invalid list options\n"));
        }
        break;
      case oVerifyOptions: {
        struct parse_options vopts[] = {
            {"show-policy-urls", VERIFY_SHOW_POLICY_URLS, NULL,
             N_("show policy URLs during signature verification")},
            {"show-notations", VERIFY_SHOW_NOTATIONS, NULL,
             N_("show all notations during signature verification")},
            {"show-std-notations", VERIFY_SHOW_STD_NOTATIONS, NULL,
             N_("show IETF standard notations during signature verification")},
            {"show-standard-notations", VERIFY_SHOW_STD_NOTATIONS, NULL, NULL},
            {"show-user-notations", VERIFY_SHOW_USER_NOTATIONS, NULL,
             N_("show user-supplied notations during signature verification")},
            {"show-keyserver-urls", VERIFY_SHOW_KEYSERVER_URLS, NULL,
             N_("show preferred keyserver URLs during signature verification")},
            {"show-uid-validity", VERIFY_SHOW_UID_VALIDITY, NULL,
             N_("show user ID validity during signature verification")},
            {"show-unusable-uids", VERIFY_SHOW_UNUSABLE_UIDS, NULL,
             N_("show revoked and expired user IDs in signature verification")},
            {"show-primary-uid-only", VERIFY_SHOW_PRIMARY_UID_ONLY, NULL,
             N_("show only the primary user ID in signature verification")},
            {NULL, 0, NULL, NULL}};

        if (!parse_options(pargs.r.ret_str, &opt.verify_options, vopts, 1)) {
          if (configname)
            log_error(_("%s:%d: invalid verify options\n"), configname,
                      configlineno);
          else
            log_error(_("invalid verify options\n"));
        }
      } break;
      case oSetNotation:
        add_notation_data(pargs.r.ret_str, 0, utf8_strings);
        add_notation_data(pargs.r.ret_str, 1, utf8_strings);
        break;
      case oSigNotation:
        add_notation_data(pargs.r.ret_str, 0, utf8_strings);
        break;
      case oCertNotation:
        add_notation_data(pargs.r.ret_str, 1, utf8_strings);
        break;
      case oUtf8Strings:
        utf8_strings = 1;
        break;
      case oNoUtf8Strings:
        utf8_strings = 0;
        break;
      case oDisableCipherAlgo: {
        int algo = string_to_cipher_algo(pargs.r.ret_str);
        gcry_cipher_ctl(NULL, GCRYCTL_DISABLE_ALGO, &algo, sizeof algo);
      } break;
      case oDisablePubkeyAlgo: {
        int algo = gcry_pk_map_name(pargs.r.ret_str);
        gcry_pk_ctl(GCRYCTL_DISABLE_ALGO, &algo, sizeof algo);
      } break;

      case oNoSigCache:
        opt.no_sig_cache = true;
        break;

      case oAllowFreeformUID:
        opt.allow_freeform_uid = true;
        break;

      case oNoAllowFreeformUID:
        opt.allow_freeform_uid = false;
        break;

      case oListOnly:
        opt.list_only = true;
        break;

      case oIgnoreTimeConflict:
        opt.ignore_time_conflict = true;
        break;

      case oIgnoreValidFrom:
        opt.ignore_valid_from = true;
        break;

      case oIgnoreCrcError:
        opt.ignore_crc_error = true;
        break;

      case oShowSessionKey:
        opt.show_session_key = 1;
        break;

      case oOverrideSessionKey:
        opt.override_session_key.resize(strlen(pargs.r.ret_str) + 1);
        strcpy((char *)opt.override_session_key.data(), pargs.r.ret_str);
        break;
      case oOverrideSessionKeyFD:
        ovrseskeyfd = translate_sys2libc_fd_int(pargs.r.ret_int, 0);
        break;
      case oMergeOnly:
        deprecated_warning(configname, configlineno, "--merge-only",
                           "--import-options ", "merge-only");
        opt.import_options |= IMPORT_MERGE_ONLY;
        break;
      case oTryAllSecrets:
        opt.try_all_secrets = true;
        break;

      case oTrustedKey:
        register_trusted_key(pargs.r.ret_str);
        break;

      case oAutoCheckTrustDB:
        opt.no_auto_check_trustdb = false;
        break;

      case oNoAutoCheckTrustDB:
        opt.no_auto_check_trustdb = true;
        break;

      case oPreservePermissions:
        opt.preserve_permissions = true;
        break;

      case oDefaultPreferenceList:
        opt.def_preference_list = pargs.r.ret_str;
        break;
      case oDefaultKeyserverURL: {
        keyserver_spec_t keyserver;
        keyserver = parse_keyserver_uri(pargs.r.ret_str, 1);
        if (!keyserver)
          log_error(_("could not parse keyserver URL\n"));
        else
          free_keyserver_spec(keyserver);

        opt.def_keyserver_url = pargs.r.ret_str;
      } break;
      case oPersonalCipherPreferences:
        pers_cipher_list = pargs.r.ret_str;
        break;
      case oPersonalDigestPreferences:
        pers_digest_list = pargs.r.ret_str;
        break;
      case oPersonalCompressPreferences:
        pers_compress_list = pargs.r.ret_str;
        break;
      case oWeakDigest:
        additional_weak_digest(pargs.r.ret_str);
        break;

      case oUnwrap:
        opt.unwrap_encryption = true;
        break;

      case oOnlySignTextIDs:
        opt.only_sign_text_ids = true;
        break;

      case oLCctype:
        opt.lc_ctype = pargs.r.ret_str;
        break;
      case oLCmessages:
        opt.lc_messages = pargs.r.ret_str;
        break;

      case oGroup:
        add_group(pargs.r.ret_str, utf8_strings);
        break;
      case oUnGroup:
        rm_group(pargs.r.ret_str);
        break;
      case oNoGroups:
        opt.grouplist.clear();
        break;

      case oEnableProgressFilter:
        opt.enable_progress_filter = true;
        break;

      case oMultifile:
        multifile = 1;
        break;
      case oKeyidFormat:
        if (ascii_strcasecmp(pargs.r.ret_str, "short") == 0)
          opt.keyid_format = KF_SHORT;
        else if (ascii_strcasecmp(pargs.r.ret_str, "long") == 0)
          opt.keyid_format = KF_LONG;
        else if (ascii_strcasecmp(pargs.r.ret_str, "0xshort") == 0)
          opt.keyid_format = KF_0xSHORT;
        else if (ascii_strcasecmp(pargs.r.ret_str, "0xlong") == 0)
          opt.keyid_format = KF_0xLONG;
        else if (ascii_strcasecmp(pargs.r.ret_str, "none") == 0)
          opt.keyid_format = KF_NONE;
        else
          log_error("unknown keyid-format '%s'\n", pargs.r.ret_str);
        break;

      case oExitOnStatusWriteError:
        opt.exit_on_status_write_error = true;
        break;

      case oLimitCardInsertTries:
        opt.limit_card_insert_tries = pargs.r.ret_int;
        break;

      case oRequireCrossCert:
        opt.flags.require_cross_cert = true;
        break;

      case oNoRequireCrossCert:
        opt.flags.require_cross_cert = false;
        break;

      case oAutoKeyLocate:
        if (!parse_auto_key_locate(pargs.r.ret_str)) {
          if (configname)
            log_error(_("%s:%d: invalid auto-key-locate list\n"), configname,
                      configlineno);
          else
            log_error(_("invalid auto-key-locate list\n"));
        }
        break;
      case oNoAutoKeyLocate:
        release_akl();
        break;

      case oEnableLargeRSA:
#if SECMEM_BUFFER_SIZE >= 65536
        opt.flags.large_rsa = true;
#else
        if (configname)
          log_info(
              "%s:%d: WARNING: gpg not built with large secure "
              "memory buffer.  Ignoring enable-large-rsa\n",
              configname, configlineno);
        else
          log_info(
              "WARNING: gpg not built with large secure "
              "memory buffer.  Ignoring --enable-large-rsa\n");
#endif /* SECMEM_BUFFER_SIZE >= 65536 */
        break;

      case oDisableLargeRSA:
        opt.flags.large_rsa = false;
        break;

      case oEnableDSA2:
        opt.flags.dsa2 = true;
        break;

      case oDisableDSA2:
        opt.flags.dsa2 = false;
        break;

      case oFakedSystemTime: {
        size_t len = strlen(pargs.r.ret_str);
        int freeze = 0;
        time_t faked_time;

        if (len > 0 && pargs.r.ret_str[len - 1] == '!') {
          freeze = 1;
          pargs.r.ret_str[len - 1] = '\0';
        }

        faked_time = isotime2epoch(pargs.r.ret_str);
        if (faked_time == (time_t)(-1))
          faked_time = (time_t)strtoul(pargs.r.ret_str, NULL, 10);
        gnupg_set_time(faked_time, freeze);
      } break;

      case oDefaultNewKeyAlgo:
        opt.def_new_key_algo = pargs.r.ret_str;
        break;

      case oNoop:
        break;

      default:
        pargs.err = configfp ? ARGPARSE_PRINT_WARNING : ARGPARSE_PRINT_ERROR;
        break;
    }
  }

  if (configfp) {
    fclose(configfp);
    configfp = NULL;
    /* Remember the first config file name. */
    if (!save_configname)
      save_configname = configname;
    else
      xfree(configname);
    configname = NULL;
    goto next_pass;
  }
  xfree(configname);
  configname = NULL;
  if (log_get_errorcount(0)) g10_exit(2);

  xfree(save_configname);
  xfree(default_configname);

  if (log_get_errorcount(0)) g10_exit(2);

  /* FIXME: We should use logging to a file only in server mode;
     however we have not yet implemetyed that.  Thus we try to get
     away with --batch as indication for logging to file
     required. */
  if (logfile && opt.batch) {
    log_set_file(logfile);
    log_set_prefix(
        NULL, GPGRT_LOG_WITH_PREFIX | GPGRT_LOG_WITH_TIME | GPGRT_LOG_WITH_PID);
  }

  if (may_coredump && !opt.quiet)
    log_info(_("WARNING: program may create a core file!\n"));

  if (opt.flags.rfc4880bis)
    log_info("WARNING: using experimental features from RFC4880bis!\n");
  else {
    opt.mimemode = 0; /* This will use text mode instead.  */
  }

  if (opt.batch) tty_batchmode(1);

  if (gnupg_faked_time_p()) {
    gnupg_isotime_t tbuf;

    log_info(_("WARNING: running with faked system time: "));
    gnupg_get_isotime(tbuf);
    dump_isotime(tbuf);
    log_printf("\n");
  }

  /* Print a warning if an argument looks like an option.  */
  if (!opt.quiet && !(pargs.flags & ARGPARSE_FLAG_STOP_SEEN)) {
    int i;

    for (i = 0; i < argc; i++)
      if (argv[i][0] == '-' && argv[i][1] == '-')
        log_info(_("Note: '%s' is not considered an option\n"), argv[i]);
  }

  gcry_control(GCRYCTL_RESUME_SECMEM_WARN);

  if (require_secmem && !got_secmem) {
    log_info(_("will not run with insecure memory due to %s\n"),
             "--require-secmem");
    g10_exit(2);
  }

  set_debug(debug_level);
  if (DBG_CLOCK) log_clock("start");

  /* Do these after the switch(), so they can override settings. */
  if (PGP6) {
    /* That does not anymore work because we have no more support
       for v3 signatures.  */
    opt.ask_sig_expire = false;
  } else if (PGP7) {
    /* That does not anymore work because we have no more support
       for v3 signatures.  */
    opt.ask_sig_expire = false;
  } else if (PGP8) {
  }

  if (def_cipher_string) {
    opt.def_cipher_algo = string_to_cipher_algo(def_cipher_string);
    xfree(def_cipher_string);
    def_cipher_string = NULL;
    if (openpgp_cipher_test_algo((cipher_algo_t)(opt.def_cipher_algo)))
      log_error(_("selected cipher algorithm is invalid\n"));
  }
  if (def_digest_string) {
    opt.def_digest_algo = string_to_digest_algo(def_digest_string);
    xfree(def_digest_string);
    def_digest_string = NULL;
    if (openpgp_md_test_algo((digest_algo_t)(opt.def_digest_algo)))
      log_error(_("selected digest algorithm is invalid\n"));
  }
  if (compress_algo_string) {
    opt.compress_algo = string_to_compress_algo(compress_algo_string);
    xfree(compress_algo_string);
    compress_algo_string = NULL;
    if (check_compress_algo(opt.compress_algo))
      log_error(_("selected compression algorithm is invalid\n"));
  }
  if (cert_digest_string) {
    opt.cert_digest_algo = string_to_digest_algo(cert_digest_string);
    xfree(cert_digest_string);
    cert_digest_string = NULL;
    if (openpgp_md_test_algo((digest_algo_t)(opt.cert_digest_algo)))
      log_error(_("selected certification digest algorithm is invalid\n"));
  }
  if (s2k_cipher_string) {
    opt.s2k_cipher_algo = string_to_cipher_algo(s2k_cipher_string);
    xfree(s2k_cipher_string);
    s2k_cipher_string = NULL;
    if (openpgp_cipher_test_algo((cipher_algo_t)(opt.s2k_cipher_algo)))
      log_error(_("selected cipher algorithm is invalid\n"));
  }
  if (s2k_digest_string) {
    opt.s2k_digest_algo = string_to_digest_algo(s2k_digest_string);
    xfree(s2k_digest_string);
    s2k_digest_string = NULL;
    if (openpgp_md_test_algo((digest_algo_t)(opt.s2k_digest_algo)))
      log_error(_("selected digest algorithm is invalid\n"));
  }
  if (opt.completes_needed < 1)
    log_error(_("completes-needed must be greater than 0\n"));
  if (opt.marginals_needed < 2)
    log_error(_("marginals-needed must be greater than 1\n"));
  if (opt.max_cert_depth < 1 || opt.max_cert_depth > 255)
    log_error(_("max-cert-depth must be in the range from 1 to 255\n"));
  if (opt.def_cert_level < 0 || opt.def_cert_level > 3)
    log_error(_("invalid default-cert-level; must be 0, 1, 2, or 3\n"));
  if (opt.min_cert_level < 1 || opt.min_cert_level > 3)
    log_error(_("invalid min-cert-level; must be 1, 2, or 3\n"));
  switch (opt.s2k_mode) {
    case 0:
      log_info(_("Note: simple S2K mode (0) is strongly discouraged\n"));
      break;
    case 1:
    case 3:
      break;
    default:
      log_error(_("invalid S2K mode; must be 0, 1 or 3\n"));
  }

  /* This isn't actually needed, but does serve to error out if the
     string is invalid. */
  if (opt.def_preference_list &&
      keygen_set_std_prefs(opt.def_preference_list->c_str(), 0))
    log_error(_("invalid default preferences\n"));

  if (pers_cipher_list && keygen_set_std_prefs(pers_cipher_list, PREFTYPE_SYM))
    log_error(_("invalid personal cipher preferences\n"));

  if (pers_digest_list && keygen_set_std_prefs(pers_digest_list, PREFTYPE_HASH))
    log_error(_("invalid personal digest preferences\n"));

  if (pers_compress_list &&
      keygen_set_std_prefs(pers_compress_list, PREFTYPE_ZIP))
    log_error(_("invalid personal compress preferences\n"));

  /* We don't support all possible commands with multifile yet */
  if (multifile) {
    const char *cmdname;

    switch (cmd) {
      case aSign:
        cmdname = "--sign";
        break;
      case aSignEncr:
        cmdname = "--sign --encrypt";
        break;
      case aClearsign:
        cmdname = "--clear-sign";
        break;
      case aDetachedSign:
        cmdname = "--detach-sign";
        break;
      case aSym:
        cmdname = "--symmetric";
        break;
      case aEncrSym:
        cmdname = "--symmetric --encrypt";
        break;
      case aStore:
        cmdname = "--store";
        break;
      default:
        cmdname = NULL;
        break;
    }

    if (cmdname)
      log_error(_("%s does not yet work with %s\n"), cmdname, "--multifile");
  }

  if (log_get_errorcount(0)) g10_exit(2);

  /* Check our chosen algorithms against the list of legal
     algorithms. */

  if (!GNUPG) {
    const char *badalg = NULL;
    preftype_t badtype = PREFTYPE_NONE;

    if (opt.def_cipher_algo &&
        !algo_available(PREFTYPE_SYM, opt.def_cipher_algo, NULL)) {
      badalg = openpgp_cipher_algo_name((cipher_algo_t)(opt.def_cipher_algo));
      badtype = PREFTYPE_SYM;
    } else if (opt.def_digest_algo &&
               !algo_available(PREFTYPE_HASH, opt.def_digest_algo, NULL)) {
      badalg = gcry_md_algo_name(opt.def_digest_algo);
      badtype = PREFTYPE_HASH;
    } else if (opt.cert_digest_algo &&
               !algo_available(PREFTYPE_HASH, opt.cert_digest_algo, NULL)) {
      badalg = gcry_md_algo_name(opt.cert_digest_algo);
      badtype = PREFTYPE_HASH;
    } else if (opt.compress_algo != -1 &&
               !algo_available(PREFTYPE_ZIP, opt.compress_algo, NULL)) {
      badalg = compress_algo_to_string(opt.compress_algo);
      badtype = PREFTYPE_ZIP;
    }

    if (badalg) {
      switch (badtype) {
        case PREFTYPE_SYM:
          log_info(_("you may not use cipher algorithm '%s'"
                     " while in %s mode\n"),
                   badalg, gnupg_compliance_option_string(opt.compliance));
          break;
        case PREFTYPE_HASH:
          log_info(_("you may not use digest algorithm '%s'"
                     " while in %s mode\n"),
                   badalg, gnupg_compliance_option_string(opt.compliance));
          break;
        case PREFTYPE_ZIP:
          log_info(_("you may not use compression algorithm '%s'"
                     " while in %s mode\n"),
                   badalg, gnupg_compliance_option_string(opt.compliance));
          break;
        default:
          BUG();
      }

      compliance_failure();
    }
  }

  /* Check our chosen algorithms against the list of allowed
   * algorithms in the current compliance mode, and fail hard if it
   * is not.  This is us being nice to the user informing her early
   * that the chosen algorithms are not available.  We also check
   * and enforce this right before the actual operation.  */
  if (opt.def_cipher_algo &&
      !gnupg_cipher_is_allowed(
          opt.compliance,
          cmd == aEncr || cmd == aSignEncr || cmd == aEncrSym || cmd == aSym ||
              cmd == aSignSym || cmd == aSignEncrSym,
          (cipher_algo_t)(opt.def_cipher_algo), GCRY_CIPHER_MODE_NONE))
    log_error(_("you may not use cipher algorithm '%s'"
                " while in %s mode\n"),
              openpgp_cipher_algo_name((cipher_algo_t)(opt.def_cipher_algo)),
              gnupg_compliance_option_string(opt.compliance));

  if (opt.def_digest_algo &&
      !gnupg_digest_is_allowed(opt.compliance,
                               cmd == aSign || cmd == aSignEncr ||
                                   cmd == aSignEncrSym || cmd == aSignSym ||
                                   cmd == aClearsign,
                               (digest_algo_t)opt.def_digest_algo))
    log_error(_("you may not use digest algorithm '%s'"
                " while in %s mode\n"),
              gcry_md_algo_name(opt.def_digest_algo),
              gnupg_compliance_option_string(opt.compliance));

  /* Fail hard.  */
  if (log_get_errorcount(0)) g10_exit(2);

  /* If there is no command but the --fingerprint is given, default
     to the --list-keys command.  */
  if (!cmd && fpr_maybe_cmd) {
    set_cmd(&cmd, aListKeys);
  }

  if (opt.verbose > 1) set_packet_list_mode(1);

  /* Add the keyrings, but not for some special commands.  We always
   * need to add the keyrings if we are running under SELinux, this
   * is so that the rings are added to the list of secured files.
   * We do not add any keyring if --no-keyring has been used.  */
  if (default_keyring >= 0) {
    if (nrings.empty() || default_keyring > 0) /* Add default ring. */
      keydb_add_resource("pubring" EXTSEP_S "kbx", KEYDB_RESOURCE_FLAG_DEFAULT);
    for (auto &nring : nrings)
      keydb_add_resource(nring.first.c_str(), nring.second);
  }

  if (pwfd != -1) /* Read the passphrase now. */
    read_passphrase_from_fd(pwfd);

  if (ovrseskeyfd != -1) /* Read the sessionkey now. */
    read_sessionkey_from_fd(ovrseskeyfd);

  fname = argc ? *argv : NULL;

  if (fname && utf8_strings) opt.flags.utf8_filename = true;

  ctrl = (ctrl_t)xcalloc(1, sizeof *ctrl);
  gpg_init_default_ctrl(ctrl);

#ifndef NO_TRUST_MODELS
  switch (cmd) {
    case aExportOwnerTrust:
      rc = setup_trustdb(0, trustdb_name);
      break;
    case aListTrustDB:
      rc = setup_trustdb(argc ? 1 : 0, trustdb_name);
      break;
    case aKeygen:
    case aFullKeygen:
    case aQuickKeygen:
      rc = setup_trustdb(1, trustdb_name);
      break;
    default:
      /* If we are using TM_ALWAYS, we do not need to create the
         trustdb.  */
      rc = setup_trustdb(opt.trust_model != TM_ALWAYS, trustdb_name);
      break;
  }
  if (rc)
    log_error(_("failed to initialize the TrustDB: %s\n"), gpg_strerror(rc));
#endif /*!NO_TRUST_MODELS*/

  switch (cmd) {
    case aStore:
    case aSym:
    case aSign:
    case aSignSym:
    case aClearsign:
      if (!opt.quiet && any_explicit_recipient)
        log_info(
            _("WARNING: recipients (-r) given "
              "without using public key encryption\n"));
      break;
    default:
      break;
  }

  /* The command dispatcher.  */
  switch (cmd) {
    case aStore: /* only store the file */
      if (argc > 1) wrong_args("--store [filename]");
      if ((rc = encrypt_store(fname))) {
        write_status_failure("store", rc);
        log_error("storing '%s' failed: %s\n", print_fname_stdin(fname),
                  gpg_strerror(rc));
      }
      break;
    case aSym: /* encrypt the given file only with the symmetric cipher */
      if (argc > 1) wrong_args("--symmetric [filename]");
      if ((rc = encrypt_symmetric(fname))) {
        write_status_failure("symencrypt", rc);
        log_error(_("symmetric encryption of '%s' failed: %s\n"),
                  print_fname_stdin(fname), gpg_strerror(rc));
      }
      break;

    case aEncr: /* encrypt the given file */
      if (multifile)
        encrypt_crypt_files(ctrl, argc, argv, remusr);
      else {
        if (argc > 1) wrong_args("--encrypt [filename]");
        if ((rc = encrypt_crypt(ctrl, -1, fname, remusr, 0, NULL, -1))) {
          write_status_failure("encrypt", rc);
          log_error("%s: encryption failed: %s\n", print_fname_stdin(fname),
                    gpg_strerror(rc));
        }
      }
      break;

    case aEncrSym:
      /* This works with PGP 8 in the sense that it acts just like a
         symmetric message.  It doesn't work at all with 2 or 6.  It
         might work with 7, but alas, I don't have a copy to test
         with right now. */
      if (argc > 1)
        wrong_args("--symmetric --encrypt [filename]");
      else if (opt.s2k_mode == 0)
        log_error(
            _("you cannot use --symmetric --encrypt"
              " with --s2k-mode 0\n"));
      else if (PGP6 || PGP7)
        log_error(_("you cannot use --symmetric --encrypt"
                    " while in %s mode\n"),
                  gnupg_compliance_option_string(opt.compliance));
      else {
        if ((rc = encrypt_crypt(ctrl, -1, fname, remusr, 1, NULL, -1))) {
          write_status_failure("encrypt", rc);
          log_error("%s: encryption failed: %s\n", print_fname_stdin(fname),
                    gpg_strerror(rc));
        }
      }
      break;

    case aSign: /* sign the given file */
    {
      std::vector<std::string> filenames;
      if (detached_sig) { /* sign all files */
        for (; argc; argc--, argv++) filenames.emplace_back(*argv);
      } else {
        if (argc > 1) wrong_args("--sign [filename]");
        if (argc) {
          filenames.emplace_back(fname);
        }
      }
      std::vector<std::pair<std::string, unsigned int>> no_remusr;
      if ((rc = sign_file(ctrl, filenames, detached_sig, locusr, 0, no_remusr,
                          NULL))) {
        write_status_failure("sign", rc);
        log_error("signing failed: %s\n", gpg_strerror(rc));
      }
    } break;

    case aSignEncr: /* sign and encrypt the given file */
    {
      std::vector<std::string> filenames;
      if (argc > 1) wrong_args("--sign --encrypt [filename]");
      if (argc) filenames.emplace_back(fname);
      if ((rc = sign_file(ctrl, filenames, detached_sig, locusr, 1, remusr,
                          NULL))) {
        write_status_failure("sign-encrypt", rc);
        log_error("%s: sign+encrypt failed: %s\n", print_fname_stdin(fname),
                  gpg_strerror(rc));
      }
    } break;

    case aSignEncrSym: /* sign and encrypt the given file */
    {
      std::vector<std::string> filenames;
      if (argc > 1)
        wrong_args("--symmetric --sign --encrypt [filename]");
      else if (opt.s2k_mode == 0)
        log_error(
            _("you cannot use --symmetric --sign --encrypt"
              " with --s2k-mode 0\n"));
      else if (PGP6 || PGP7)
        log_error(_("you cannot use --symmetric --sign --encrypt"
                    " while in %s mode\n"),
                  gnupg_compliance_option_string(opt.compliance));
      else {
        if (argc) filenames.emplace_back(fname);

        if ((rc = sign_file(ctrl, filenames, detached_sig, locusr, 2, remusr,
                            NULL))) {
          write_status_failure("sign-encrypt", rc);
          log_error("%s: symmetric+sign+encrypt failed: %s\n",
                    print_fname_stdin(fname), gpg_strerror(rc));
        }
      }
    } break;

    case aSignSym: /* sign and conventionally encrypt the given file */
      if (argc > 1) wrong_args("--sign --symmetric [filename]");
      rc = sign_symencrypt_file(ctrl, fname, locusr);
      if (rc) {
        write_status_failure("sign-symencrypt", rc);
        log_error("%s: sign+symmetric failed: %s\n", print_fname_stdin(fname),
                  gpg_strerror(rc));
      }
      break;

    case aClearsign: /* make a clearsig */
      if (argc > 1) wrong_args("--clear-sign [filename]");
      if ((rc = clearsign_file(ctrl, fname, locusr, NULL))) {
        write_status_failure("sign", rc);
        log_error("%s: clear-sign failed: %s\n", print_fname_stdin(fname),
                  gpg_strerror(rc));
      }
      break;

    case aVerify:
      if (multifile) {
        if ((rc = verify_files(ctrl, argc, argv)))
          log_error("verify files failed: %s\n", gpg_strerror(rc));
      } else {
        if ((rc = verify_signatures(ctrl, argc, argv)))
          log_error("verify signatures failed: %s\n", gpg_strerror(rc));
      }
      if (rc) write_status_failure("verify", rc);
      break;

    case aDecrypt:
      if (multifile)
        decrypt_messages(ctrl, argc, argv);
      else {
        if (argc > 1) wrong_args("--decrypt [filename]");
        if ((rc = decrypt_message(ctrl, fname))) {
          write_status_failure("decrypt", rc);
          log_error("decrypt_message failed: %s\n", gpg_strerror(rc));
        }
      }
      break;

    case aQuickSignKey:
    case aQuickLSignKey: {
      const char *fpr;
      std::vector<std::pair<std::string, unsigned int>> uids;

      if (argc < 1) wrong_args("--quick-[l]sign-key fingerprint [userids]");
      fpr = *argv++;
      argc--;
      for (; argc; argc--, argv++)
        uids.emplace_back(str_to_utf8(*argv, utf8_strings), 0);
      keyedit_quick_sign(ctrl, fpr, uids, locusr, (cmd == aQuickLSignKey));
    } break;

    case aSignKey:
      if (argc != 1) wrong_args("--sign-key user-id");
    /* fall through */
    case aLSignKey: {
      std::vector<std::string> commands;

      if (argc != 1) wrong_args("--lsign-key user-id");
      /* fall through */

      if (cmd == aSignKey)
        commands.emplace_back("sign");
      else if (cmd == aLSignKey)
        commands.emplace_back("lsign");
      else
        BUG();

      commands.emplace_back("save");
      std::string username = str_to_utf8(fname, utf8_strings);
      keyedit_menu(ctrl, username.c_str(), locusr, commands, 0, 0);
    } break;

    case aEditKey: /* Edit a key signature */
    {
      std::vector<std::string> commands;

      if (!argc) wrong_args("--edit-key user-id [commands]");
      std::string username = str_to_utf8(fname, utf8_strings);
      if (argc > 1) {
        for (argc--, argv++; argc; argc--, argv++) commands.emplace_back(*argv);
        keyedit_menu(ctrl, username.c_str(), locusr, commands, 0, 1);
      } else
        keyedit_menu(ctrl, username.c_str(), locusr, commands, 0, 1);
    } break;

    case aPasswd:
      if (argc != 1)
        wrong_args("--change-passphrase <user-id>");
      else {
        std::string username = str_to_utf8(fname, utf8_strings);
        keyedit_passwd(ctrl, username.c_str());
      }
      break;

    case aDeleteKeys:
    case aDeleteSecretKeys:
    case aDeleteSecretAndPublicKeys: {
      std::vector<std::string> names;
      /* I'm adding these in reverse order as add_to_strlist2
         reverses them again, and it's easier to understand in the
         proper order :) */
      for (; argc; argc--)
        names.emplace(names.begin(), str_to_utf8(argv[argc - 1], utf8_strings));
      delete_keys(ctrl, names, cmd == aDeleteSecretKeys,
                  cmd == aDeleteSecretAndPublicKeys);
    } break;

    case aCheckKeys:
      opt.check_sigs = true; /* fall through */
    case aListSigs:
      opt.list_sigs = true; /* fall through */
    case aListKeys: {
      std::vector<std::string> list;
      for (; argc; argc--, argv++)
        list.emplace(list.begin(), str_to_utf8(*argv, utf8_strings));
      public_key_list(ctrl, list, 0);
    } break;
    case aListSecretKeys: {
      std::vector<std::string> list;
      for (; argc; argc--, argv++)
        list.emplace(list.begin(), str_to_utf8(*argv, utf8_strings));
      secret_key_list(ctrl, list);
    } break;
    case aLocateKeys: {
      std::vector<std::string> list;
      for (; argc; argc--, argv++)
        list.emplace(list.begin(), str_to_utf8(*argv, utf8_strings));
      public_key_list(ctrl, list, 1);
    } break;

    case aQuickKeygen: {
      const char *x_algo, *x_usage, *x_expire;

      if (argc < 1 || argc > 4)
        wrong_args("--quick-generate-key USER-ID [ALGO [USAGE [EXPIRE]]]");
      std::string username = str_to_utf8(fname, utf8_strings);
      argv++, argc--;
      x_algo = "";
      x_usage = "";
      x_expire = "";
      if (argc) {
        x_algo = *argv++;
        argc--;
        if (argc) {
          x_usage = *argv++;
          argc--;
          if (argc) {
            x_expire = *argv++;
            argc--;
          }
        }
      }
      quick_generate_keypair(ctrl, username.c_str(), x_algo, x_usage, x_expire);
    } break;

    case aKeygen: /* generate a key */
      if (opt.batch) {
        if (argc > 1) wrong_args("--generate-key [parameterfile]");
        generate_keypair(ctrl, 0, argc ? *argv : NULL, NULL, 0);
      } else {
        if (opt.command_fd != -1 && argc) {
          if (argc > 1) wrong_args("--generate-key [parameterfile]");

          opt.batch = 1;
          generate_keypair(ctrl, 0, argc ? *argv : NULL, NULL, 0);
        } else if (argc)
          wrong_args("--generate-key");
        else
          generate_keypair(ctrl, 0, NULL, NULL, 0);
      }
      break;

    case aFullKeygen: /* Generate a key with all options. */
      if (opt.batch) {
        if (argc > 1) wrong_args("--full-generate-key [parameterfile]");
        generate_keypair(ctrl, 1, argc ? *argv : NULL, NULL, 0);
      } else {
        if (argc) wrong_args("--full-generate-key");
        generate_keypair(ctrl, 1, NULL, NULL, 0);
      }
      break;

    case aQuickAddUid: {
      const char *uid, *newuid;

      if (argc != 2) wrong_args("--quick-add-uid USER-ID NEW-USER-ID");
      uid = *argv++;
      argc--;
      newuid = *argv++;
      argc--;
      keyedit_quick_adduid(ctrl, uid, newuid);
    } break;

    case aQuickAddKey: {
      const char *x_fpr, *x_algo, *x_usage, *x_expire;

      if (argc < 1 || argc > 4)
        wrong_args("--quick-add-key FINGERPRINT [ALGO [USAGE [EXPIRE]]]");
      x_fpr = *argv++;
      argc--;
      x_algo = "";
      x_usage = "";
      x_expire = "";
      if (argc) {
        x_algo = *argv++;
        argc--;
        if (argc) {
          x_usage = *argv++;
          argc--;
          if (argc) {
            x_expire = *argv++;
            argc--;
          }
        }
      }
      keyedit_quick_addkey(ctrl, x_fpr, x_algo, x_usage, x_expire);
    } break;

    case aQuickRevUid: {
      const char *uid, *uidtorev;

      if (argc != 2) wrong_args("--quick-revoke-uid USER-ID USER-ID-TO-REVOKE");
      uid = *argv++;
      argc--;
      uidtorev = *argv++;
      argc--;
      keyedit_quick_revuid(ctrl, uid, uidtorev);
    } break;

    case aQuickSetExpire: {
      const char *x_fpr, *x_expire;

      if (argc != 2) wrong_args("--quick-set-exipre FINGERPRINT EXPIRE");
      x_fpr = *argv++;
      argc--;
      x_expire = *argv++;
      argc--;
      keyedit_quick_set_expire(ctrl, x_fpr, x_expire);
    } break;

    case aQuickSetPrimaryUid: {
      const char *uid, *primaryuid;

      if (argc != 2)
        wrong_args("--quick-set-primary-uid USER-ID PRIMARY-USER-ID");
      uid = *argv++;
      argc--;
      primaryuid = *argv++;
      argc--;
      keyedit_quick_set_primary(ctrl, uid, primaryuid);
    } break;

    case aFastImport:
      opt.import_options |= IMPORT_FAST; /* fall through */
    case aImport:
      import_keys(ctrl, argc ? argv : NULL, argc, NULL, opt.import_options);
      break;

    case aExport:
    case aSendKeys:
    case aRecvKeys: {
      std::vector<std::string> users;
      for (; argc; argc--, argv++)
        users.emplace_back(str_to_utf8(*argv, utf8_strings));
      if (cmd == aSendKeys)
        rc = keyserver_export(ctrl, users);
      else if (cmd == aRecvKeys)
        rc = keyserver_import(ctrl, users);
      else {
        export_stats_t stats = export_new_stats();
        rc = export_pubkeys(ctrl, users, opt.export_options, stats);
        export_print_stats(stats);
        export_release_stats(stats);
      }
      if (rc) {
        if (cmd == aSendKeys) {
          write_status_failure("send-keys", rc);
          log_error(_("keyserver send failed: %s\n"), gpg_strerror(rc));
        } else if (cmd == aRecvKeys) {
          write_status_failure("recv-keys", rc);
          log_error(_("keyserver receive failed: %s\n"), gpg_strerror(rc));
        } else {
          write_status_failure("export", rc);
          log_error(_("key export failed: %s\n"), gpg_strerror(rc));
        }
      }
    } break;

    case aExportSshKey:
      if (argc != 1) wrong_args("--export-ssh-key <user-id>");
      rc = export_ssh_key(ctrl, argv[0]);
      if (rc) {
        write_status_failure("export-ssh-key", rc);
        log_error(_("export as ssh key failed: %s\n"), gpg_strerror(rc));
      }
      break;

    case aSearchKeys: {
      std::vector<std::string> tokens;
      for (; argc; argc--, argv++)
        tokens.emplace_back(str_to_utf8(*argv, utf8_strings));
      rc = keyserver_search(ctrl, tokens);
      if (rc) {
        write_status_failure("search-keys", rc);
        log_error(_("keyserver search failed: %s\n"), gpg_strerror(rc));
      }
    } break;

    case aRefreshKeys: {
      std::vector<std::string> users;
      for (; argc; argc--, argv++)
        users.emplace_back(str_to_utf8(*argv, utf8_strings));
      rc = keyserver_refresh(ctrl, users);
      if (rc) {
        write_status_failure("refresh-keys", rc);
        log_error(_("keyserver refresh failed: %s\n"), gpg_strerror(rc));
      }
    } break;

    case aFetchKeys: {
      std::vector<std::string> urilist;
      for (; argc; argc--, argv++)
        urilist.emplace(urilist.begin(), str_to_utf8(*argv, utf8_strings));
      rc = keyserver_fetch(ctrl, urilist);
      if (rc) {
        write_status_failure("fetch-keys", rc);
        log_error("key fetch failed: %s\n", gpg_strerror(rc));
      }
    } break;

    case aExportSecret: {
      std::vector<std::string> users;

      for (; argc; argc--, argv++)
        users.emplace_back(str_to_utf8(*argv, utf8_strings));
      {
        export_stats_t stats = export_new_stats();
        export_seckeys(ctrl, users, opt.export_options, stats);
        export_print_stats(stats);
        export_release_stats(stats);
      }
    } break;

    case aExportSecretSub: {
      std::vector<std::string> users;

      for (; argc; argc--, argv++)
        users.emplace_back(str_to_utf8(*argv, utf8_strings));
      {
        export_stats_t stats = export_new_stats();
        export_secsubkeys(ctrl, users, opt.export_options, stats);
        export_print_stats(stats);
        export_release_stats(stats);
      }
    } break;

    case aGenRevoke: {
      if (argc != 1) wrong_args("--generate-revocation user-id");
      std::string username = str_to_utf8(*argv, utf8_strings);
      gen_revoke(ctrl, username.c_str());
    } break;

    case aDesigRevoke: {
      if (argc != 1) wrong_args("--generate-designated-revocation user-id");
      std::string username = str_to_utf8(*argv, utf8_strings);
      gen_desig_revoke(ctrl, username.c_str(), locusr);
    } break;

#ifndef NO_TRUST_MODELS
    case aListTrustDB:
      if (!argc)
        list_trustdb(ctrl, es_stdout, NULL);
      else {
        for (; argc; argc--, argv++) list_trustdb(ctrl, es_stdout, *argv);
      }
      break;

    case aUpdateTrustDB:
      if (argc) wrong_args("--update-trustdb");
      update_trustdb(ctrl);
      break;

    case aCheckTrustDB:
      /* Old versions allowed for arguments - ignore them */
      check_trustdb(ctrl);
      break;

    case aListTrustPath: {
      if (!argc) wrong_args("--list-trust-path <user-ids>");
      for (; argc; argc--, argv++) {
        std::string username = str_to_utf8(*argv, utf8_strings);
        list_trust_path(username.c_str());
      }
    } break;

    case aExportOwnerTrust:
      if (argc) wrong_args("--export-ownertrust");
      export_ownertrust(ctrl);
      break;

    case aImportOwnerTrust:
      if (argc > 1) wrong_args("--import-ownertrust [file]");
      import_ownertrust(ctrl, argc ? *argv : NULL);
      break;
#endif /*!NO_TRUST_MODELS*/

#ifdef ENABLE_CARD_SUPPORT
    case aCardStatus:
      if (argc == 0)
        card_status(ctrl, es_stdout, NULL);
      else if (argc == 1)
        card_status(ctrl, es_stdout, *argv);
      else
        wrong_args("--card-status [serialno]");
      break;

    case aCardEdit:
      if (argc) {
        std::vector<std::string> commands;
        for (argc--, argv++; argc; argc--, argv++)
          commands.emplace(commands.begin(), *argv);
        card_edit(ctrl, commands);
      } else {
        std::vector<std::string> commands;
        card_edit(ctrl, commands);
      }
      break;

    case aChangePIN:
      if (!argc)
        change_pin(0, 1);
      else if (argc == 1)
        change_pin(atoi(*argv), 1);
      else
        wrong_args("--change-pin [no]");
      break;
#endif /* ENABLE_CARD_SUPPORT*/

    default:
      if (!opt.quiet)
        log_info(
            _("WARNING: no command supplied."
              "  Trying to guess what you mean ...\n"));
    /*FALLTHRU*/
    case aListPackets:
      if (argc > 1) wrong_args("[filename]");
      /* Issue some output for the unix newbie */
      if (!fname && !opt.outfile && gnupg_isatty(fileno(stdin)) &&
          gnupg_isatty(fileno(stdout)) && gnupg_isatty(fileno(stderr)))
        log_info(_("Go ahead and type your message ...\n"));

      a = iobuf_open(fname);
      if (a && is_secured_file(iobuf_get_fd(a))) {
        iobuf_close(a);
        a = NULL;
        gpg_err_set_errno(EPERM);
      }
      if (!a)
        log_error(_("can't open '%s'\n"), print_fname_stdin(fname));
      else {
        if (!opt.no_armor) {
          if (use_armor_filter(a)) {
            afx = new_armor_context();
            push_armor_filter(afx, a);
          }
        }
        if (cmd == aListPackets) {
          opt.list_packets = true;
          set_packet_list_mode(1);
        }
        rc = proc_packets(ctrl, NULL, a);
        if (rc) {
          write_status_failure("-", rc);
          log_error("processing message failed: %s\n", gpg_strerror(rc));
        }
        iobuf_close(a);
      }
      break;
  }

  /* cleanup */
  gpg_deinit_default_ctrl(ctrl);
  xfree(ctrl);
  release_armor_context(afx);
  g10_exit(0);
  return 8; /*NEVER REACHED*/
}

void g10_exit(int rc) {
  if (DBG_CLOCK) log_clock("stop");

  if ((opt.debug & DBG_MEMSTAT_VALUE)) {
    keydb_dump_stats();
    sig_check_dump_stats();
    gcry_control(GCRYCTL_DUMP_MEMORY_STATS);
  }
  if (opt.debug) gcry_control(GCRYCTL_DUMP_SECMEM_STATS);

  gcry_control(GCRYCTL_TERM_SECMEM);

  rc = rc ? rc : log_get_errorcount(0) ? 2 : g10_errors_seen ? 1 : 0;
  exit(rc);
}

/****************
 * Check the supplied name,value string and add it to the notation
 * data to be used for signatures.  which==0 for sig notations, and 1
 * for cert notations.
*/
static void add_notation_data(const char *string, int which,
                              bool utf8_strings) {
  struct notation *notation;

  notation = string_to_notation(string, utf8_strings);
  if (notation) {
    if (which) {
      notation->next = opt.cert_notations;
      opt.cert_notations = notation;
    } else {
      notation->next = opt.sig_notations;
      opt.sig_notations = notation;
    }
  }
}

static void add_policy_url(const char *string, int which) {
  unsigned int i, critical = 0;

  if (*string == '!') {
    string++;
    critical = 1;
  }

  for (i = 0; i < strlen(string); i++)
    if (!isascii(string[i]) || iscntrl(string[i])) break;

  if (i == 0 || i < strlen(string)) {
    if (which)
      log_error(_("the given certification policy URL is invalid\n"));
    else
      log_error(_("the given signature policy URL is invalid\n"));
  }

  if (which)
    opt.cert_policy_url.emplace_back(string, critical ? 1 : 0);
  else
    opt.sig_policy_url.emplace_back(string, critical ? 1 : 0);
}

static void add_keyserver_url(const char *string, int which) {
  unsigned int i, critical = 0;

  if (*string == '!') {
    string++;
    critical = 1;
  }

  for (i = 0; i < strlen(string); i++)
    if (!isascii(string[i]) || iscntrl(string[i])) break;

  if (i == 0 || i < strlen(string)) {
    if (which)
      BUG();
    else
      log_error(_("the given preferred keyserver URL is invalid\n"));
  }

  if (which)
    BUG();
  else
    opt.sig_keyserver_url.emplace_back(string, critical ? 1 : 0);
}

static void read_sessionkey_from_fd(int fd) {
  int i, len;

  if (!gnupg_fd_valid(fd))
    log_fatal("override-session-key-fd is invalid: %s\n", strerror(errno));

  for (i = len = 100;; i++) {
    if (i >= len - 1) {
      len += 100;
      opt.override_session_key.reserve(len);
    }
    if (read(fd, &opt.override_session_key[i], 1) != 1 ||
        opt.override_session_key[i] == '\n')
      break;
  }
  opt.override_session_key[i] = 0;
  log_debug("seskey: %s\n", opt.override_session_key.data());
}
