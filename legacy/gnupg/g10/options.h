/* options.h
 * Copyright (C) 1998, 1999, 2000, 2001, 2002, 2003, 2004, 2005, 2006,
 *               2007, 2010, 2011 Free Software Foundation, Inc.
 * Copyright (C) 2015 g10 Code GmbH
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
#ifndef G10_OPTIONS_H
#define G10_OPTIONS_H

#include <boost/optional.hpp>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include <botan/secmem.h>

#include <stdint.h>
#include <sys/types.h>
#include "../common/compliance.h"
#include "../common/types.h"
#include "main.h"
#include "packet.h"

/* Declaration of a keyserver spec type.  The definition is found in
   ../common/keyserver.h.  */
struct keyserver_spec;
typedef struct keyserver_spec *keyserver_spec_t;

enum { KF_DEFAULT, KF_NONE, KF_SHORT, KF_LONG, KF_0xSHORT, KF_0xLONG };

enum {
  TM_CLASSIC = 0,
  TM_PGP = 1,
  TM_EXTERNAL = 2,
  TM_ALWAYS,
  TM_DIRECT,
  TM_AUTO
};

enum { AKL_NODEFAULT, AKL_LOCAL, AKL_CERT, AKL_LDAP, AKL_KEYSERVER, AKL_SPEC };

struct akl {
  int type;
  keyserver_spec_t spec;
  struct akl *next;
};

#define DBG_PACKET_VALUE 1    /* debug packet reading/writing */
#define DBG_MPI_VALUE 2       /* debug mpi details */
#define DBG_CRYPTO_VALUE 4    /* debug crypto handling */
                              /* (may reveal sensitive data) */
#define DBG_FILTER_VALUE 8    /* debug internal filter handling */
#define DBG_IOBUF_VALUE 16    /* debug iobuf stuff */
#define DBG_MEMORY_VALUE 32   /* debug memory allocation stuff */
#define DBG_CACHE_VALUE 64    /* debug the caching */
#define DBG_MEMSTAT_VALUE 128 /* show memory statistics */
#define DBG_TRUST_VALUE 256   /* debug the trustdb */
#define DBG_HASHING_VALUE 512 /* debug hashing operations */
#define DBG_IPC_VALUE 1024    /* debug assuan communication */
#define DBG_CLOCK_VALUE 4096
#define DBG_LOOKUP_VALUE 8192   /* debug the key lookup */
#define DBG_EXTPROG_VALUE 16384 /* debug external program calls */

/* Tests for the debugging flags.  */
#define DBG_PACKET (opt.debug & DBG_PACKET_VALUE)
#define DBG_MPI (opt.debug & DBG_MPI_VALUE)
#define DBG_CRYPTO (opt.debug & DBG_CRYPTO_VALUE)
#define DBG_FILTER (opt.debug & DBG_FILTER_VALUE)
#define DBG_CACHE (opt.debug & DBG_CACHE_VALUE)
#define DBG_TRUST (opt.debug & DBG_TRUST_VALUE)
#define DBG_HASHING (opt.debug & DBG_HASHING_VALUE)
#define DBG_IPC (opt.debug & DBG_IPC_VALUE)
#define DBG_IPC (opt.debug & DBG_IPC_VALUE)
#define DBG_CLOCK (opt.debug & DBG_CLOCK_VALUE)
#define DBG_LOOKUP (opt.debug & DBG_LOOKUP_VALUE)
#define DBG_EXTPROG (opt.debug & DBG_EXTPROG_VALUE)

/* FIXME: We need to check why we did not put this into opt. */
#define DBG_MEMORY memory_debug_mode
#define DBG_MEMSTAT memory_stat_debug_mode

extern int memory_debug_mode;
extern int memory_stat_debug_mode;

/* Compatibility flags.  */
#define GNUPG (opt.compliance == CO_GNUPG || opt.compliance == CO_DE_VS)
#define RFC4880 (opt.compliance == CO_RFC4880)
#define PGP6 (opt.compliance == CO_PGP6)
#define PGP7 (opt.compliance == CO_PGP7)
#define PGP8 (opt.compliance == CO_PGP8)
#define PGPX (PGP6 || PGP7 || PGP8)

/* Various option flags.  Note that there should be no common string
   names between the IMPORT_ and EXPORT_ flags as they can be mixed in
   the keyserver-options option. */

#define IMPORT_LOCAL_SIGS (1 << 0)
#define IMPORT_REPAIR_PKS_SUBKEY_BUG (1 << 1)
#define IMPORT_FAST (1 << 2)
#define IMPORT_SHOW (1 << 3)
#define IMPORT_MERGE_ONLY (1 << 4)
#define IMPORT_MINIMAL (1 << 5)
#define IMPORT_CLEAN (1 << 6)
#define IMPORT_NO_SECKEY (1 << 7)
#define IMPORT_KEEP_OWNERTTRUST (1 << 8)
#define IMPORT_EXPORT (1 << 9)
#define IMPORT_RESTORE (1 << 10)
#define IMPORT_REPAIR_KEYS (1 << 11)

#define EXPORT_LOCAL_SIGS (1 << 0)
#define EXPORT_ATTRIBUTES (1 << 1)
#define EXPORT_SENSITIVE_REVKEYS (1 << 2)
#define EXPORT_RESET_SUBKEY_PASSWD (1 << 3)
#define EXPORT_MINIMAL (1 << 4)
#define EXPORT_CLEAN (1 << 5)
#define EXPORT_BACKUP (1 << 10)

#define LIST_SHOW_POLICY_URLS (1 << 1)
#define LIST_SHOW_STD_NOTATIONS (1 << 2)
#define LIST_SHOW_USER_NOTATIONS (1 << 3)
#define LIST_SHOW_NOTATIONS (LIST_SHOW_STD_NOTATIONS | LIST_SHOW_USER_NOTATIONS)
#define LIST_SHOW_KEYSERVER_URLS (1 << 4)
#define LIST_SHOW_UID_VALIDITY (1 << 5)
#define LIST_SHOW_UNUSABLE_UIDS (1 << 6)
#define LIST_SHOW_UNUSABLE_SUBKEYS (1 << 7)
#define LIST_SHOW_KEYRING (1 << 8)
#define LIST_SHOW_SIG_EXPIRE (1 << 9)
#define LIST_SHOW_SIG_SUBPACKETS (1 << 10)
#define LIST_SHOW_USAGE (1 << 11)

#define VERIFY_SHOW_POLICY_URLS (1 << 1)
#define VERIFY_SHOW_STD_NOTATIONS (1 << 2)
#define VERIFY_SHOW_USER_NOTATIONS (1 << 3)
#define VERIFY_SHOW_NOTATIONS \
  (VERIFY_SHOW_STD_NOTATIONS | VERIFY_SHOW_USER_NOTATIONS)
#define VERIFY_SHOW_KEYSERVER_URLS (1 << 4)
#define VERIFY_SHOW_UID_VALIDITY (1 << 5)
#define VERIFY_SHOW_UNUSABLE_UIDS (1 << 6)
#define VERIFY_SHOW_PRIMARY_UID_ONLY (1 << 9)

#define KEYSERVER_HTTP_PROXY (1 << 0)
#define KEYSERVER_TIMEOUT (1 << 1)
#define KEYSERVER_ADD_FAKE_V3 (1 << 2)
#define KEYSERVER_AUTO_KEY_RETRIEVE (1 << 3)

/* Global options for GPG.  */
struct options {
  int verbose{0};
  bool quiet{false};
  unsigned debug{0};
  bool armor{false};
  boost::optional<std::string> outfile;
  estream_t outfp{0}; /* Hack, sometimes used in place of outfile.  */
  off_t max_output{0};

  bool dry_run{false};
  bool list_only{false};
  bool mimemode{false};
  bool textmode{false};
  bool expert{false};
  boost::optional<std::string> def_sig_expire{"0"};
  bool ask_sig_expire{false};
  boost::optional<std::string> def_cert_expire{"0"};
  bool ask_cert_expire{false};
  bool batch{false};      /* run in batch mode */
  bool answer_yes{false}; /* answer yes on most questions */
  bool answer_no{false};  /* answer no on most questions */
  bool check_sigs{false}; /* check key signatures */
  bool with_colons{false};
  bool with_key_data{false};
  bool with_icao_spelling{false}; /* Print ICAO spelling with fingerprints.  */
  bool with_fingerprint{false};   /* Option --with-fingerprint active.  */
  bool with_subkey_fingerprint{
      false};               /* Option --with-subkey-fingerprint active.  */
  bool with_keygrip{false}; /* Option --with-keygrip active.  */
  bool with_secret{false};  /* Option --with-secret active.  */
  int fingerprint{0};       /* list fingerprints */
  bool list_sigs{false};    /* list signatures */
  bool no_armor{false};
  bool list_packets{false}; /* Option --list-packets active.  */
  int def_cipher_algo{0};
  int def_digest_algo{0};
  int cert_digest_algo{0};
  int compress_algo{-1}; /* defaults to DEFAULT_COMPRESS_ALGO */
  std::vector<std::pair<std::string, unsigned int>> def_secret_key;
  boost::optional<std::string> def_recipient;
  int def_recipient_self{0};
  std::vector<std::string> secret_keys_to_try;

  /* A list of mail addresses (addr-spec) provided by the user with
   * the option --sender.  */
  std::vector<std::string> sender_list;

  int def_cert_level{0};
  int min_cert_level{2};
  int ask_cert_level{0};
  int marginals_needed{3};
  int completes_needed{1};
  int max_cert_depth{5};

  boost::optional<std::string> def_new_key_algo;

  /* Options to be passed to the gpg-agent */
  boost::optional<std::string> lc_ctype;
  boost::optional<std::string> lc_messages;

  bool skip_verify{false};
  bool skip_hidden_recipients{false};

  /* TM_CLASSIC must be zero to accommodate trustdbsg generated before
     we started storing the trust model inside the trustdb. */
  int trust_model
#ifdef NO_TRUST_MODELS
  {
    TM_ALWAYS
  }
#else
  {
    TM_AUTO
  }
#endif
  ;
  int force_ownertrust{0};
  enum gnupg_compliance_mode compliance { CO_GNUPG };
  int keyid_format{KF_NONE};
  bool throw_keyids{false};
  int s2k_mode{3}; /* iterated+salted */
  int s2k_digest_algo{0};
  int s2k_cipher_algo{DEFAULT_CIPHER_ALGO};
  /* This is the encoded form, not the raw count */
  unsigned char s2k_count{0};          /* Auto-calibrate when needed.  */
  keyserver_spec_t keyserver{nullptr}; /* The list of configured keyservers.  */
  struct {
    unsigned int options{0};
    unsigned int import_options{
        (IMPORT_REPAIR_KEYS | IMPORT_REPAIR_PKS_SUBKEY_BUG)};
    unsigned int export_options{EXPORT_ATTRIBUTES};
    boost::optional<std::string> http_proxy;
  } keyserver_options;
  unsigned int import_options{IMPORT_REPAIR_KEYS};
  unsigned int export_options{EXPORT_ATTRIBUTES};
  unsigned int list_options{(LIST_SHOW_UID_VALIDITY | LIST_SHOW_USAGE)};
  unsigned int verify_options{
      (LIST_SHOW_UID_VALIDITY | VERIFY_SHOW_POLICY_URLS |
       VERIFY_SHOW_STD_NOTATIONS | VERIFY_SHOW_KEYSERVER_URLS)};
  boost::optional<std::string> def_preference_list;
  boost::optional<std::string> def_keyserver_url;
  std::vector<prefitem_t> personal_cipher_prefs;
  std::vector<prefitem_t> personal_digest_prefs;
  std::vector<prefitem_t> personal_compress_prefs;
  std::set<enum gcry_md_algos> weak_digests;
  bool no_perm_warn{false};
  bool no_encrypt_to{false};
  int encrypt_to_default_key{0};
  bool interactive{false};
  struct notation *sig_notations{nullptr};
  struct notation *cert_notations{nullptr};
  std::vector<std::pair<std::string, unsigned int>> sig_policy_url;
  std::vector<std::pair<std::string, unsigned int>> cert_policy_url;
  std::vector<std::pair<std::string, unsigned int>> sig_keyserver_url;
  bool allow_freeform_uid{false};
  bool ignore_time_conflict{false};
  bool ignore_valid_from{false};
  bool ignore_crc_error{false};
  int command_fd{-1};
  Botan::secure_vector<uint8_t> override_session_key;
  bool show_session_key{false};

  bool try_all_secrets{false};
  bool no_sig_cache{false};
  bool no_auto_check_trustdb{false};
  bool preserve_permissions{false};
  std::vector<groupitem> grouplist;
  bool enable_progress_filter{false};
  unsigned int screen_columns{0};
  unsigned int screen_lines{0};
  byte *show_subpackets{nullptr};

  /* If true, let write failures on the status-fd exit the process. */
  bool exit_on_status_write_error{false};

  /* If > 0, limit the number of card insertion prompts to this
     value. */
  int limit_card_insert_tries{0};

  struct {
    /* If set, require an 0x19 backsig to be present on signatures
       made by signing subkeys.  If not set, a missing backsig is not
       an error (but an invalid backsig still is). */
    bool require_cross_cert{true};

    bool utf8_filename{false};
    bool dsa2{false};
    bool large_rsa{false};
    bool disable_signer_uid{false};
    /* Flag to enbale experimental features from RFC4880bis.  */
    bool rfc4880bis{false};
  } flags;

  /* Linked list of ways to find a key if the key isn't on the local
     keyring. */
  struct akl *auto_key_locate{nullptr};

  bool unwrap_encryption{false};
  int only_sign_text_ids{false};
};
extern struct options gpg2_opt;
#define opt gpg2_opt

/* CTRL is used to keep some global variables we currently can't
   avoid.  Future concurrent versions of gpg will put it into a per
   request structure CTRL. */
struct glo_ctrl {
  int in_auto_key_retrieve{0}; /* True if we are doing an
                                  auto_key_retrieve. */
  /* Hack to store the last error.  We currently need it because the
     proc_packet machinery is not able to reliabale return error
     codes.  Thus for the --server purposes we store some of the error
     codes here.  FIXME! */
  gpg_error_t lasterr{0};

  bool shown_experimental_digest_warning{false};
  std::set<enum gcry_md_algos> shown_rejection_notice;
};
extern struct glo_ctrl glo_ctrl;

#endif /*G10_OPTIONS_H*/
