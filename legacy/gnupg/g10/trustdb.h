/* trustdb.h - Trust database
 * Copyright (C) 1998, 1999, 2000, 2001, 2002, 2003, 2004,
 *               2005, 2012 Free Software Foundation, Inc.
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

#ifndef G10_TRUSTDB_H
#define G10_TRUSTDB_H

/* Trust values must be sorted in ascending order! */
#define TRUST_MASK 15
#define TRUST_UNKNOWN 0   /* o: not yet calculated/assigned */
#define TRUST_EXPIRED 1   /* e: calculation may be invalid */
#define TRUST_UNDEFINED 2 /* q: not enough information for calculation */
#define TRUST_NEVER 3     /* n: never trust this pubkey */
#define TRUST_MARGINAL 4  /* m: marginally trusted */
#define TRUST_FULLY 5     /* f: fully trusted      */
#define TRUST_ULTIMATE 6  /* u: ultimately trusted */
/* Trust values not covered by the mask. */
#define TRUST_FLAG_REVOKED 32        /* r: revoked */
#define TRUST_FLAG_SUB_REVOKED 64    /* r: revoked but for subkeys */
#define TRUST_FLAG_DISABLED 128      /* d: key/uid disabled */
#define TRUST_FLAG_PENDING_CHECK 256 /* a check-trustdb is pending */

/* Length of the hash used to select UIDs in keyedit.c.  */
#define NAMEHASH_LEN 20

/*
 * A structure to store key identification as well as some stuff needed
 * for validation
 */
struct key_item {
  struct key_item *next;
  unsigned int ownertrust, min_ownertrust;
  byte trust_depth;
  byte trust_value;
  char *trust_regexp;
  u32 kid[2];
};

/*
 * Check whether the signature SIG is in the klist K.
 */
static inline struct key_item *is_in_klist(struct key_item *k,
                                           PKT_signature *sig) {
  for (; k; k = k->next) {
    if (k->kid[0] == sig->keyid[0] && k->kid[1] == sig->keyid[1]) return k;
  }
  return NULL;
}

/*-- trust.c --*/
int cache_disabled_value(ctrl_t ctrl, PKT_public_key *pk);
void register_trusted_keyid(u32 *keyid);
void register_trusted_key(const char *string);

const char *trust_value_to_string(unsigned int value);
int string_to_trust_value(const char *str);
const char *uid_trust_string_fixed(ctrl_t ctrl, PKT_public_key *key,
                                   PKT_user_id *uid);

unsigned int get_ownertrust(ctrl_t ctrl, PKT_public_key *pk);
void update_ownertrust(ctrl_t ctrl, PKT_public_key *pk, unsigned int new_trust);
int clear_ownertrusts(ctrl_t ctrl, PKT_public_key *pk);

void revalidation_mark(ctrl_t ctrl);
void check_trustdb_stale(ctrl_t ctrl);
void check_or_update_trustdb(ctrl_t ctrl);

unsigned int get_validity(ctrl_t ctrl, kbnode_t kb, PKT_public_key *pk,
                          PKT_user_id *uid, PKT_signature *sig, int may_ask);
int get_validity_info(ctrl_t ctrl, kbnode_t kb, PKT_public_key *pk,
                      PKT_user_id *uid);
const char *get_validity_string(ctrl_t ctrl, PKT_public_key *pk,
                                PKT_user_id *uid);

void mark_usable_uid_certs(ctrl_t ctrl, kbnode_t keyblock, kbnode_t uidnode,
                           u32 *main_kid, struct key_item *klist, u32 curtime,
                           u32 *next_expire);

void clean_one_uid(ctrl_t ctrl, kbnode_t keyblock, kbnode_t uidnode, int noisy,
                   int self_only, int *uids_cleaned, int *sigs_cleaned);
void clean_key(ctrl_t ctrl, kbnode_t keyblock, int noisy, int self_only,
               int *uids_cleaned, int *sigs_cleaned);

/*-- trustdb.c --*/
void tdb_register_trusted_keyid(u32 *keyid);
void tdb_register_trusted_key(const char *string);
/* Returns whether KID is on the list of ultimately trusted keys.  */
int tdb_keyid_is_utk(u32 *kid);
/* Return the list of ultimately trusted keys.  The caller must not
 * modify this list nor must it free the list.  */
struct key_item *tdb_utks(void);
void check_trustdb(ctrl_t ctrl);
void update_trustdb(ctrl_t ctrl);
int setup_trustdb(int level, const char *dbname);
const char *trust_model_string(int model);
gpg_error_t init_trustdb(ctrl_t ctrl, int no_create);
int have_trustdb(ctrl_t ctrl);
void tdb_check_trustdb_stale(ctrl_t ctrl);
void tdb_revalidation_mark(ctrl_t ctrl);
int trustdb_pending_check(void);
void tdb_check_or_update(ctrl_t ctrl);

int tdb_cache_disabled_value(ctrl_t ctrl, PKT_public_key *pk);

unsigned int tdb_get_validity_core(ctrl_t ctrl, kbnode_t kb, PKT_public_key *pk,
                                   PKT_user_id *uid, PKT_public_key *main_pk,
                                   PKT_signature *sig, int may_ask);

void list_trust_path(const char *username);
int enum_cert_paths(void **context, unsigned long *lid, unsigned *ownertrust,
                    unsigned *validity);
void enum_cert_paths_print(void **context, FILE *fp, int refresh,
                           unsigned long selected_lid);

void read_trust_options(ctrl_t ctrl, byte *trust_model, unsigned long *created,
                        unsigned long *nextcheck, byte *marginals,
                        byte *completes, byte *cert_depth,
                        byte *min_cert_level);

unsigned int tdb_get_ownertrust(ctrl_t ctrl, PKT_public_key *pk, int no_create);
unsigned int tdb_get_min_ownertrust(ctrl_t ctrl, PKT_public_key *pk,
                                    int no_create);
int get_ownertrust_info(ctrl_t ctrl, PKT_public_key *pk, int no_create);
const char *get_ownertrust_string(ctrl_t ctrl, PKT_public_key *pk,
                                  int no_create);

void tdb_update_ownertrust(ctrl_t ctrl, PKT_public_key *pk,
                           unsigned int new_trust);
int tdb_clear_ownertrusts(ctrl_t ctrl, PKT_public_key *pk);

/*-- tdbdump.c --*/
void list_trustdb(ctrl_t ctrl, estream_t fp, const char *username);
void export_ownertrust(ctrl_t ctrl);
void import_ownertrust(ctrl_t ctrl, const char *fname);

/*-- pkclist.c --*/
int edit_ownertrust(ctrl_t ctrl, PKT_public_key *pk, int mode);

#endif /*G10_TRUSTDB_H*/
