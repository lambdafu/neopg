/* keyserver.c - generic keyserver code
 * Copyright (C) 2001, 2002, 2003, 2004, 2005, 2006, 2007, 2008,
 *               2009, 2011, 2012 Free Software Foundation, Inc.
 * Copyright (C) 2014 Werner Koch
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

#include <boost/algorithm/string/join.hpp>

#include "../common/iobuf.h"
#include "../common/mbox-util.h"
#include "../common/status.h"
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

#ifdef HAVE_W32_SYSTEM
/* It seems Vista doesn't grok X_OK and so fails access() tests.
   Previous versions interpreted X_OK as F_OK anyway, so we'll just
   use F_OK directly. */
#undef X_OK
#define X_OK F_OK
#endif /* HAVE_W32_SYSTEM */

struct keyrec {
  KEYDB_SEARCH_DESC desc;
  u32 createtime, expiretime;
  int size, flags;
  byte type;
  IOBUF uidbuf;
  unsigned int lines;
};

/* Parameters for the search line handler.  */
struct search_line_handler_parm_s {
  ctrl_t ctrl;             /* The session control structure.  */
  char *searchstr_disp;    /* Native encoded search string or NULL.  */
  KEYDB_SEARCH_DESC *desc; /* Array with search descriptions.  */
  int count;               /* Number of keys we are currently prepared to
                              handle.  This is the size of the DESC array.  If
                              it is too small, it will grow safely.  */
  int validcount;          /* Enable the "Key x-y of z" messages. */
  int nkeys;               /* Number of processed records.  */
  int any_lines;           /* At least one line has been processed.  */
  unsigned int numlines;   /* Counter for displayed lines.  */
  int eof_seen;            /* EOF encountered.  */
  int not_found;           /* Set if no keys have been found.  */
};

enum ks_action { KS_UNKNOWN = 0, KS_GET, KS_GETNAME, KS_SEND, KS_SEARCH };

static struct parse_options keyserver_opts[] = {
    /* some of these options are not real - just for the help
       message */
    {"max-cert-size", 0, NULL, NULL}, /* MUST be the first in this array! */
    {"http-proxy", KEYSERVER_HTTP_PROXY, NULL, /* MUST be the second!  */
     N_("override proxy options set for dirmngr")},

    {"include-revoked", 0, NULL, N_("include revoked keys in search results")},
    {"include-subkeys", 0, NULL,
     N_("include subkeys when searching by key ID")},
    {"timeout", KEYSERVER_TIMEOUT, NULL,
     N_("override timeout options set for dirmngr")},
    {"auto-key-retrieve", KEYSERVER_AUTO_KEY_RETRIEVE, NULL,
     N_("automatically retrieve keys when verifying signatures")},
    {NULL, 0, NULL, NULL}};

static gpg_error_t keyserver_get(ctrl_t ctrl, KEYDB_SEARCH_DESC *desc,
                                 int ndesc,
                                 struct keyserver_spec *override_keyserver,
                                 int quick, unsigned char **r_fpr,
                                 size_t *r_fprlen);
static gpg_error_t keyserver_put(ctrl_t ctrl,
                                 const std::vector<std::string> &keyspecs);

/* Reasonable guess.  The commonly used test key simon.josefsson.org
   is larger than 32k, thus we need at least this value. */
#define DEFAULT_MAX_CERT_SIZE 65536

static size_t max_cert_size = DEFAULT_MAX_CERT_SIZE;

static void warn_kshelper_option(char *option, int noisy) {
  char *p;

  if ((p = strchr(option, '='))) *p = 0;

  if (!strcmp(option, "ca-cert-file"))
    log_info(
        "keyserver option '%s' is obsolete; please use "
        "'%s' in dirmngr.conf\n",
        "ca-cert-file", "hkp-cacert");
  else if (!strcmp(option, "check-cert") ||
           !strcmp(option, "broken-http-proxy"))
    log_info("keyserver option '%s' is obsolete\n", option);
  else if (noisy || opt.verbose)
    log_info("keyserver option '%s' is unknown\n", option);
}

/* Called from main to parse the args for --keyserver-options.  */
int parse_keyserver_options(char *options) {
  int ret = 1;
  char *tok;
  char *max_cert = NULL;
  char *http_proxy = NULL;

  keyserver_opts[0].value = &max_cert;
  keyserver_opts[0].value = &http_proxy;

  while ((tok = optsep(&options))) {
    if (tok[0] == '\0') continue;

    /* We accept quite a few possible options here - some options to
       handle specially, the keyserver_options list, and import and
       export options that pertain to keyserver operations.  */

    if (!parse_options(tok, &opt.keyserver_options.options, keyserver_opts,
                       0) &&
        !parse_import_options(tok, &opt.keyserver_options.import_options, 0) &&
        !parse_export_options(tok, &opt.keyserver_options.export_options, 0)) {
      /* All of the standard options have failed, so the option was
         destined for a keyserver plugin as used by GnuPG < 2.1 */
      warn_kshelper_option(tok, 1);
    }
  }

  opt.keyserver_options.http_proxy.emplace(http_proxy);

  if (max_cert) {
    max_cert_size = strtoul(max_cert, (char **)NULL, 10);

    if (max_cert_size == 0) max_cert_size = DEFAULT_MAX_CERT_SIZE;
  }

  return ret;
}

/* Return 0 for match */
static int cmp_keyserver_spec(struct keyserver_spec *one,
                              struct keyserver_spec *two) {
  if (ascii_strcasecmp(one->uri.scheme.c_str(), two->uri.scheme.c_str()) == 0)
    if (ascii_strcasecmp(one->uri.host.c_str(), two->uri.host.c_str()) == 0)
      if (one->uri.port == two->uri.port) return 0;

  return 1;
}

/* Try and match one of our keyservers.  If we can, return that.  If
   we can't, return our input. */
struct keyserver_spec *keyserver_match(struct keyserver_spec *spec) {
  struct keyserver_spec *ks;

  for (auto &ks : opt.keyserver)
    if (cmp_keyserver_spec(spec, ks) == 0) return ks;

  return spec;
}

keyserver_spec_t parse_keyserver_uri(const char *string, int require_scheme) {
  int assume_hkp = 0;
  struct keyserver_spec *keyserver;
  const char *idx;
  int count;
  char *uri, *duped_uri, *options;

  log_assert(string);

  keyserver = new keyserver_spec;

  uri = xstrdup(string);
  options = strchr(uri, ' ');
  if (options) {
    char *tok;

    *options = '\0';
    options++;

    while ((tok = optsep(&options))) warn_kshelper_option(tok, 0);
  }

  keyserver->uri.set_uri(uri);
  xfree(uri);
  if (require_scheme && keyserver->uri.scheme.empty()) return NULL;

  /* Assume HKP if there is no scheme */
  assume_hkp = 1;
  keyserver->uri.scheme = "hkp";

  if (ascii_strcasecmp(keyserver->uri.scheme.c_str(), "x-hkp") == 0) {
    /* Canonicalize this to "hkp" so it works with both the internal
       and external keyserver interface. */
    keyserver->uri.scheme = "hkp";
  }

  return keyserver;

fail:
  delete keyserver;
  return NULL;
}

static void print_keyrec(ctrl_t ctrl, int number, struct keyrec *keyrec) {
  int i;

  iobuf_writebyte(keyrec->uidbuf, 0);
  iobuf_flush_temp(keyrec->uidbuf);
  es_printf("(%d)\t%s  ", number, iobuf_get_temp_buffer(keyrec->uidbuf));

  if (keyrec->size > 0) es_printf("%d bit ", keyrec->size);

  if (keyrec->type) {
    const char *str;

    str = openpgp_pk_algo_name((pubkey_algo_t)(keyrec->type));

    if (str && strcmp(str, "?"))
      es_printf("%s ", str);
    else
      es_printf("unknown ");
  }

  switch (keyrec->desc.mode) {
    /* If the keyserver helper gave us a short keyid, we have no
       choice but to use it.  Do check --keyid-format to add a 0x if
       needed. */
    case KEYDB_SEARCH_MODE_SHORT_KID:
      es_printf(
          "key %s%08lX",
          (opt.keyid_format == KF_0xSHORT || opt.keyid_format == KF_0xLONG)
              ? "0x"
              : "",
          (unsigned long)keyrec->desc.u.kid[1]);
      break;

    /* However, if it gave us a long keyid, we can honor
       --keyid-format via keystr(). */
    case KEYDB_SEARCH_MODE_LONG_KID:
      es_printf("key %s", keystr(keyrec->desc.u.kid));
      break;

    /* If it gave us a PGP 2.x fingerprint, not much we can do
       beyond displaying it. */
    case KEYDB_SEARCH_MODE_FPR16:
      es_printf("key ");
      for (i = 0; i < 16; i++) es_printf("%02X", keyrec->desc.u.fpr[i]);
      break;

    /* If we get a modern fingerprint, we have the most
       flexibility. */
    case KEYDB_SEARCH_MODE_FPR20: {
      u32 kid[2];
      keyid_from_fingerprint(ctrl, keyrec->desc.u.fpr, 20, kid);
      es_printf("key %s", keystr(kid));
    } break;

    default:
      BUG();
      break;
  }

  if (keyrec->createtime > 0) {
    es_printf(", ");
    es_printf(_("created: %s"), strtimestamp(keyrec->createtime));
  }

  if (keyrec->expiretime > 0) {
    es_printf(", ");
    es_printf(_("expires: %s"), strtimestamp(keyrec->expiretime));
  }

  if (keyrec->flags & 1) es_printf(" (%s)", _("revoked"));
  if (keyrec->flags & 2) es_printf(" (%s)", _("disabled"));
  if (keyrec->flags & 4) es_printf(" (%s)", _("expired"));

  es_printf("\n");
}

/* Returns a keyrec (which must be freed) once a key is complete, and
   NULL otherwise.  Call with a NULL keystring once key parsing is
   complete to return any unfinished keys. */
static struct keyrec *parse_keyrec(char *keystring) {
  /* FIXME: Remove the static and put the data into the parms we use
     for the caller anyway.  */
  static struct keyrec *work = NULL;
  struct keyrec *ret = NULL;
  char *record;
  int i;

  if (keystring == NULL) {
    if (work == NULL)
      return NULL;
    else if (work->desc.mode == KEYDB_SEARCH_MODE_NONE) {
      xfree(work);
      return NULL;
    } else {
      ret = work;
      work = NULL;
      return ret;
    }
  }

  if (work == NULL) {
    work = (keyrec *)xmalloc_clear(sizeof(struct keyrec));
    work->uidbuf = iobuf_temp();
  }

  trim_trailing_ws((unsigned char *)(keystring), strlen(keystring));

  if ((record = gpg_strsep(&keystring, ":")) == NULL) return ret;

  if (ascii_strcasecmp("pub", record) == 0) {
    char *tok;
    gpg_error_t err;

    if (work->desc.mode) {
      ret = work;
      work = (keyrec *)xmalloc_clear(sizeof(struct keyrec));
      work->uidbuf = iobuf_temp();
    }

    if ((tok = gpg_strsep(&keystring, ":")) == NULL) return ret;

    err = classify_user_id(tok, &work->desc, 1);
    if (err || (work->desc.mode != KEYDB_SEARCH_MODE_SHORT_KID &&
                work->desc.mode != KEYDB_SEARCH_MODE_LONG_KID &&
                work->desc.mode != KEYDB_SEARCH_MODE_FPR16 &&
                work->desc.mode != KEYDB_SEARCH_MODE_FPR20)) {
      work->desc.mode = KEYDB_SEARCH_MODE_NONE;
      return ret;
    }

    /* Note all items after this are optional.  This allows us to
       have a pub line as simple as pub:keyid and nothing else. */

    work->lines++;

    if ((tok = gpg_strsep(&keystring, ":")) == NULL) return ret;

    work->type = atoi(tok);

    if ((tok = gpg_strsep(&keystring, ":")) == NULL) return ret;

    work->size = atoi(tok);

    if ((tok = gpg_strsep(&keystring, ":")) == NULL) return ret;

    if (atoi(tok) <= 0)
      work->createtime = 0;
    else
      work->createtime = atoi(tok);

    if ((tok = gpg_strsep(&keystring, ":")) == NULL) return ret;

    if (atoi(tok) <= 0)
      work->expiretime = 0;
    else {
      work->expiretime = atoi(tok);
      /* Force the 'e' flag on if this key is expired. */
      if (work->expiretime <= make_timestamp()) work->flags |= 4;
    }

    if ((tok = gpg_strsep(&keystring, ":")) == NULL) return ret;

    while (*tok) switch (*tok++) {
        case 'r':
        case 'R':
          work->flags |= 1;
          break;

        case 'd':
        case 'D':
          work->flags |= 2;
          break;

        case 'e':
        case 'E':
          work->flags |= 4;
          break;
      }
  } else if (ascii_strcasecmp("uid", record) == 0 && work->desc.mode) {
    char *userid, *tok;

    if ((tok = gpg_strsep(&keystring, ":")) == NULL) return ret;

    if (strlen(tok) == 0) return ret;

    userid = tok;

    /* By definition, de-%-encoding is always smaller than the
       original string so we can decode in place. */

    i = 0;

    while (*tok)
      if (tok[0] == '%' && tok[1] && tok[2]) {
        int c;

        userid[i] = (c = hextobyte(&tok[1])) == -1 ? '?' : c;
        i++;
        tok += 3;
      } else
        userid[i++] = *tok++;

    /* We don't care about the other info provided in the uid: line
       since no keyserver supports marking userids with timestamps
       or revoked/expired/disabled yet. */

    /* No need to check for control characters, as utf8_to_native
       does this for us. */

    std::string decoded = utf8_to_native(userid, i, 0);
    if (strlen(decoded.c_str()) > opt.screen_columns - 10)
      decoded[opt.screen_columns - 10] = '\0';
    iobuf_writestr(work->uidbuf, decoded.c_str());
    iobuf_writestr(work->uidbuf, "\n\t");
    work->lines++;
  }

  /* Ignore any records other than "pri" and "uid" for easy future
     growth. */

  return ret;
}

/* Show a prompt and allow the user to select keys for retrieval.  */
static gpg_error_t show_prompt(ctrl_t ctrl, KEYDB_SEARCH_DESC *desc,
                               int numdesc, int count, const char *search) {
  gpg_error_t err;
  char *answer = NULL;

  es_fflush(es_stdout);

  if (count && opt.command_fd == -1) {
    static int from = 1;
    tty_printf("Keys %d-%d of %d for \"%s\".  ", from, numdesc, count, search);
    from = numdesc + 1;
  }

again:
  err = 0;
  xfree(answer);
  answer = cpr_get_no_help("keysearch.prompt",
                           _("Enter number(s), N)ext, or Q)uit > "));
  /* control-d */
  if (answer[0] == '\x04') {
    tty_printf("Q\n");
    answer[0] = 'q';
  }

  if (answer[0] == 'q' || answer[0] == 'Q')
    err = GPG_ERR_CANCELED;
  else if (atoi(answer) >= 1 && atoi(answer) <= numdesc) {
    char *split = answer;
    char *num;
    int numarray[50];
    int numidx = 0;
    int idx;

    while ((num = gpg_strsep(&split, " ,")))
      if (atoi(num) >= 1 && atoi(num) <= numdesc) {
        if (numidx >= DIM(numarray)) {
          tty_printf("Too many keys selected\n");
          goto again;
        }
        numarray[numidx++] = atoi(num);
      }

    if (!numidx) goto again;

    {
      KEYDB_SEARCH_DESC *selarray;

      selarray = (KEYDB_SEARCH_DESC *)xtrymalloc(numidx * sizeof *selarray);
      if (!selarray) {
        err = gpg_error_from_syserror();
        goto leave;
      }
      for (idx = 0; idx < numidx; idx++)
        selarray[idx] = desc[numarray[idx] - 1];
      err = keyserver_get(ctrl, selarray, numidx, NULL, 0, NULL, NULL);
      xfree(selarray);
    }
  }

leave:
  xfree(answer);
  return err;
}

/* This is a callback used by call-dirmngr.c to process the result of
   KS_SEARCH command.  If SPECIAL is 0, LINE is the actual data line
   received with all escaping removed and guaranteed to be exactly one
   line with stripped LF; an EOF is indicated by LINE passed as NULL.
   If special is 1, the line contains the source of the information
   (usually an URL).  LINE may be modified after return.  */
static gpg_error_t search_line_handler(void *opaque, int special, char *line) {
  struct search_line_handler_parm_s *parm =
      (search_line_handler_parm_s *)opaque;
  gpg_error_t err = 0;
  struct keyrec *keyrec;

  if (special == 1) {
    log_info("data source: %s\n", line);
    return 0;
  } else if (special) {
    log_debug("unknown value %d for special search callback", special);
    return 0;
  }

  if (parm->eof_seen && line) {
    log_debug("ooops: unexpected data after EOF\n");
    line = NULL;
  }

  /* Print the received line.  */
  if (opt.with_colons && line) {
    es_printf("%s\n", line);
  }

  /* Look for an info: line.  The only current info: values defined
     are the version and key count. */
  if (line && !parm->any_lines && !ascii_strncasecmp("info:", line, 5)) {
    char *str = line + 5;
    char *tok;

    if ((tok = gpg_strsep(&str, ":"))) {
      int version;

      if (sscanf(tok, "%d", &version) != 1) version = 1;

      if (version != 1) {
        log_error(_("invalid keyserver protocol "
                    "(us %d!=handler %d)\n"),
                  1, version);
        return GPG_ERR_UNSUPPORTED_PROTOCOL;
      }
    }

    if ((tok = gpg_strsep(&str, ":")) && sscanf(tok, "%d", &parm->count) == 1) {
      if (!parm->count)
        parm->not_found = 1; /* Server indicated that no items follow.  */
      else if (parm->count < 0)
        parm->count = 10; /* Bad value - assume something reasonable.  */
      else
        parm->validcount = 1; /* COUNT seems to be okay.  */
    }

    parm->any_lines = 1;
    return 0; /* Line processing finished.  */
  }

again:
  if (line)
    keyrec = parse_keyrec(line);
  else {
    /* Received EOF - flush data */
    parm->eof_seen = 1;
    keyrec = parse_keyrec(NULL);
    if (!keyrec) {
      if (!parm->nkeys)
        parm->not_found = 1; /* No keys at all.  */
      else {
        if (parm->nkeys != parm->count) parm->validcount = 0;

        if (!(opt.with_colons && opt.batch)) {
          err = show_prompt(parm->ctrl, parm->desc, parm->nkeys,
                            parm->validcount ? parm->count : 0,
                            parm->searchstr_disp);
          return err;
        }
      }
    }
  }

  /* Save the key in the key array.  */
  if (keyrec) {
    /* Allocate or enlarge the key array if needed.  */
    if (!parm->desc) {
      if (parm->count < 1) {
        parm->count = 10;
        parm->validcount = 0;
      }
      parm->desc =
          (KEYDB_SEARCH_DESC *)xtrymalloc(parm->count * sizeof *parm->desc);
      if (!parm->desc) {
        err = gpg_error_from_syserror();
        iobuf_close(keyrec->uidbuf);
        xfree(keyrec);
        return err;
      }
    } else if (parm->nkeys == parm->count) {
      /* Keyserver sent more keys than claimed in the info: line. */
      KEYDB_SEARCH_DESC *tmp;
      int newcount = parm->count + 10;

      tmp = (KEYDB_SEARCH_DESC *)xtryrealloc(parm->desc,
                                             newcount * sizeof *parm->desc);
      if (!tmp) {
        err = gpg_error_from_syserror();
        iobuf_close(keyrec->uidbuf);
        xfree(keyrec);
        return err;
      }
      parm->count = newcount;
      parm->desc = tmp;
      parm->validcount = 0;
    }

    parm->desc[parm->nkeys] = keyrec->desc;

    if (!opt.with_colons) {
      /* SCREEN_LINES - 1 for the prompt. */
      if (parm->numlines + keyrec->lines > opt.screen_lines - 1) {
        err = show_prompt(parm->ctrl, parm->desc, parm->nkeys,
                          parm->validcount ? parm->count : 0,
                          parm->searchstr_disp);
        if (err) return err;
        parm->numlines = 0;
      }

      print_keyrec(parm->ctrl, parm->nkeys + 1, keyrec);
    }

    parm->numlines += keyrec->lines;
    iobuf_close(keyrec->uidbuf);
    xfree(keyrec);

    parm->any_lines = 1;
    parm->nkeys++;

    /* If we are here due to a flush after the EOF, run again for
       the last prompt.  Fixme: Make this code better readable. */
    if (parm->eof_seen) goto again;
  }

  return 0;
}

int keyserver_export(ctrl_t ctrl, const std::vector<std::string> &users) {
  gpg_error_t err;
  std::vector<std::string> sl;
  KEYDB_SEARCH_DESC desc;
  int rc = 0;

  /* Weed out descriptors that we don't support sending */
  for (auto &user : users) {
    err = classify_user_id(user.c_str(), &desc, 1);
    if (err || (desc.mode != KEYDB_SEARCH_MODE_SHORT_KID &&
                desc.mode != KEYDB_SEARCH_MODE_LONG_KID &&
                desc.mode != KEYDB_SEARCH_MODE_FPR16 &&
                desc.mode != KEYDB_SEARCH_MODE_FPR20)) {
      log_error(_("\"%s\" not a key ID: skipping\n"), user.c_str());
      continue;
    } else
      sl.emplace_back(user);
  }

  if (!sl.empty()) {
    rc = keyserver_put(ctrl, sl);
  }

  return rc;
}

/* Structure to convey the arg to keyserver_retrieval_screener.  */
struct ks_retrieval_screener_arg_s {
  KEYDB_SEARCH_DESC *desc;
  int ndesc;
};

/* Check whether a key matches the search description.  The function
   returns 0 if the key shall be imported.  */
static gpg_error_t keyserver_retrieval_screener(kbnode_t keyblock,
                                                void *opaque) {
  struct ks_retrieval_screener_arg_s *arg =
      (ks_retrieval_screener_arg_s *)opaque;
  KEYDB_SEARCH_DESC *desc = arg->desc;
  int ndesc = arg->ndesc;
  kbnode_t node;
  PKT_public_key *pk;
  int n;
  u32 keyid[2];
  byte fpr[MAX_FINGERPRINT_LEN];
  size_t fpr_len = 0;

  /* Secret keys are not expected from a keyserver.  We do not
     care about secret subkeys because the import code takes care
     of skipping them.  Not allowing an import of a public key
     with a secret subkey would make it too easy to inhibit the
     downloading of a public key.  Recall that keyservers do only
     limited checks.  */
  node = find_kbnode(keyblock, PKT_SECRET_KEY);
  if (node) return GPG_ERR_GENERAL; /* Do not import. */

  if (!ndesc) return 0; /* Okay if no description given.  */

  /* Loop over all key packets.  */
  for (node = keyblock; node; node = node->next) {
    if (node->pkt->pkttype != PKT_PUBLIC_KEY &&
        node->pkt->pkttype != PKT_PUBLIC_SUBKEY)
      continue;

    pk = node->pkt->pkt.public_key;
    fingerprint_from_pk(pk, fpr, &fpr_len);
    keyid_from_pk(pk, keyid);

    /* Compare requested and returned fingerprints if available. */
    for (n = 0; n < ndesc; n++) {
      if (desc[n].mode == KEYDB_SEARCH_MODE_FPR20) {
        if (fpr_len == 20 && !memcmp(fpr, desc[n].u.fpr, 20)) return 0;
      } else if (desc[n].mode == KEYDB_SEARCH_MODE_FPR16) {
        if (fpr_len == 16 && !memcmp(fpr, desc[n].u.fpr, 16)) return 0;
      } else if (desc[n].mode == KEYDB_SEARCH_MODE_LONG_KID) {
        if (keyid[0] == desc[n].u.kid[0] && keyid[1] == desc[n].u.kid[1])
          return 0;
      } else if (desc[n].mode == KEYDB_SEARCH_MODE_SHORT_KID) {
        if (keyid[1] == desc[n].u.kid[1]) return 0;
      } else      /* No keyid or fingerprint - can't check.  */
        return 0; /* allow import.  */
    }
  }

  return GPG_ERR_GENERAL;
}

int keyserver_import(ctrl_t ctrl, const std::vector<std::string> &users) {
  gpg_error_t err;
  KEYDB_SEARCH_DESC *desc;
  int num = 100, count = 0;
  int rc = 0;

  /* Build a list of key ids */
  desc = (KEYDB_SEARCH_DESC *)xmalloc(sizeof(KEYDB_SEARCH_DESC) * num);

  for (auto &user : users) {
    err = classify_user_id(user.c_str(), &desc[count], 1);
    if (err || (desc[count].mode != KEYDB_SEARCH_MODE_SHORT_KID &&
                desc[count].mode != KEYDB_SEARCH_MODE_LONG_KID &&
                desc[count].mode != KEYDB_SEARCH_MODE_FPR16 &&
                desc[count].mode != KEYDB_SEARCH_MODE_FPR20)) {
      log_error(_("\"%s\" not a key ID: skipping\n"), user.c_str());
      continue;
    }

    count++;
    if (count == num) {
      num += 100;
      desc =
          (KEYDB_SEARCH_DESC *)xrealloc(desc, sizeof(KEYDB_SEARCH_DESC) * num);
    }
  }

  if (count > 0) rc = keyserver_get(ctrl, desc, count, NULL, 0, NULL, NULL);

  xfree(desc);

  return rc;
}

/* Return true if any keyserver has been configured. */
int keyserver_any_configured(ctrl_t ctrl) {
  return !gpg_dirmngr_ks_list(ctrl, NULL);
}

/* Import all keys that exactly match NAME */
int keyserver_import_name(ctrl_t ctrl, const char *name, unsigned char **fpr,
                          size_t *fprlen, struct keyserver_spec *keyserver) {
  KEYDB_SEARCH_DESC desc;

  memset(&desc, 0, sizeof desc);

  desc.mode = KEYDB_SEARCH_MODE_EXACT;
  desc.u.name = name;

  return keyserver_get(ctrl, &desc, 1, keyserver, 0, fpr, fprlen);
}

int keyserver_import_fprint(ctrl_t ctrl, const byte *fprint, size_t fprint_len,
                            struct keyserver_spec *keyserver, int quick) {
  KEYDB_SEARCH_DESC desc;

  memset(&desc, 0, sizeof(desc));

  if (fprint_len == 16)
    desc.mode = KEYDB_SEARCH_MODE_FPR16;
  else if (fprint_len == 20)
    desc.mode = KEYDB_SEARCH_MODE_FPR20;
  else
    return -1;

  memcpy(desc.u.fpr, fprint, fprint_len);

  /* TODO: Warn here if the fingerprint we got doesn't match the one
     we asked for? */
  return keyserver_get(ctrl, &desc, 1, keyserver, quick, NULL, NULL);
}

int keyserver_import_keyid(ctrl_t ctrl, u32 *keyid,
                           struct keyserver_spec *keyserver, int quick) {
  KEYDB_SEARCH_DESC desc;

  memset(&desc, 0, sizeof(desc));

  desc.mode = KEYDB_SEARCH_MODE_LONG_KID;
  desc.u.kid[0] = keyid[0];
  desc.u.kid[1] = keyid[1];

  return keyserver_get(ctrl, &desc, 1, keyserver, quick, NULL, NULL);
}

/* code mostly stolen from do_export_stream */
static int keyidlist(ctrl_t ctrl, const std::vector<std::string> &users,
                     KEYDB_SEARCH_DESC **klist, int *count) {
  int rc = 0;
  int num = 100;
  kbnode_t keyblock = NULL;
  kbnode_t node;
  KEYDB_HANDLE kdbhd;
  int ndesc;
  KEYDB_SEARCH_DESC *desc = NULL;

  *count = 0;

  *klist = (KEYDB_SEARCH_DESC *)xmalloc(sizeof(KEYDB_SEARCH_DESC) * num);

  kdbhd = keydb_new();
  if (!kdbhd) {
    rc = gpg_error_from_syserror();
    goto leave;
  }
  keydb_disable_caching(kdbhd); /* We are looping the search.  */

  if (users.empty()) {
    ndesc = 1;
    desc = (KEYDB_SEARCH_DESC *)xmalloc_clear(ndesc * sizeof *desc);
    desc[0].mode = KEYDB_SEARCH_MODE_FIRST;
  } else {
    desc = (KEYDB_SEARCH_DESC *)xmalloc(users.size() * sizeof *desc);

    ndesc = 0;
    for (auto &user : users) {
      gpg_error_t err;
      if (!(err = classify_user_id(user.c_str(), desc + ndesc, 1)))
        ndesc++;
      else
        log_error(_("key \"%s\" not found: %s\n"), user.c_str(),
                  gpg_strerror(err));
    }
  }

  for (;;) {
    rc = keydb_search(kdbhd, desc, ndesc, NULL);
    if (rc) break; /* ready.  */

    if (users.empty()) desc[0].mode = KEYDB_SEARCH_MODE_NEXT;

    /* read the keyblock */
    rc = keydb_get_keyblock(kdbhd, &keyblock);
    if (rc) {
      log_error(_("error reading keyblock: %s\n"), gpg_strerror(rc));
      goto leave;
    }

    if ((node = find_kbnode(keyblock, PKT_PUBLIC_KEY))) {
      /* v4 keys get full fingerprints.  v3 keys get long keyids.
         This is because it's easy to calculate any sort of keyid
         from a v4 fingerprint, but not a v3 fingerprint. */

      if (node->pkt->pkt.public_key->version < 4) {
        (*klist)[*count].mode = KEYDB_SEARCH_MODE_LONG_KID;
        keyid_from_pk(node->pkt->pkt.public_key, (*klist)[*count].u.kid);
      } else {
        size_t dummy;

        (*klist)[*count].mode = KEYDB_SEARCH_MODE_FPR20;
        fingerprint_from_pk(node->pkt->pkt.public_key, (*klist)[*count].u.fpr,
                            &dummy);
      }

      (*count)++;

      if (*count == num) {
        num += 100;
        *klist = (KEYDB_SEARCH_DESC *)xrealloc(*klist,
                                               sizeof(KEYDB_SEARCH_DESC) * num);
      }
    }
  }

  if (rc == GPG_ERR_NOT_FOUND) rc = 0;

leave:
  if (rc) {
    xfree(*klist);
    *klist = NULL;
  }
  xfree(desc);
  keydb_release(kdbhd);
  release_kbnode(keyblock);

  return rc;
}

/* Note this is different than the original HKP refresh.  It allows
   usernames to refresh only part of the keyring. */

gpg_error_t keyserver_refresh(ctrl_t ctrl,
                              const std::vector<std::string> &users) {
  gpg_error_t err;
  int count, numdesc;
  KEYDB_SEARCH_DESC *desc;
  unsigned int options = opt.keyserver_options.import_options;

  /* We switch merge-only on during a refresh, as 'refresh' should
     never import new keys, even if their keyids match. */
  opt.keyserver_options.import_options |= IMPORT_MERGE_ONLY;

  /* Similarly, we switch on fast-import, since refresh may make
     multiple import sets (due to preferred keyserver URLs).  We don't
     want each set to rebuild the trustdb.  Instead we do it once at
     the end here. */
  opt.keyserver_options.import_options |= IMPORT_FAST;

  err = keyidlist(ctrl, users, &desc, &numdesc);
  if (err) return err;

  count = numdesc;
  if (count > 0) {
    char *tmpuri;

    err = gpg_dirmngr_ks_list(ctrl, &tmpuri);
    if (!err) {
      if (!opt.quiet) {
        log_info(ngettext("refreshing %d key from %s\n",
                          "refreshing %d keys from %s\n", count),
                 count, tmpuri);
      }
      xfree(tmpuri);

      err = keyserver_get(ctrl, desc, numdesc, NULL, 0, NULL, NULL);
    }
  }

  xfree(desc);

  opt.keyserver_options.import_options = options;

  /* If the original options didn't have fast import, and the trustdb
     is dirty, rebuild. */
  if (!(opt.keyserver_options.import_options & IMPORT_FAST))
    check_or_update_trustdb(ctrl);

  return err;
}

/* Search for keys on the keyservers.  The patterns are given in the
   string list TOKENS.  */
gpg_error_t keyserver_search(ctrl_t ctrl,
                             const std::vector<std::string> &tokens) {
  gpg_error_t err;
  struct search_line_handler_parm_s parm;

  memset(&parm, 0, sizeof parm);

  if (tokens.empty()) return 0; /* Return success if no patterns are given.  */

  /* Write global options */

  /* for(temp=opt.keyserver_options.other;temp;temp=temp->next) */
  /*   es_fprintf(spawn->tochild,"OPTION %s\n",temp->d); */

  /* Write per-keyserver options */

  /* for(temp=keyserver->options;temp;temp=temp->next) */
  /*   es_fprintf(spawn->tochild,"OPTION %s\n",temp->d); */

  std::string searchstr = boost::algorithm::join(tokens, " ");

  /* FIXME: Enable the next line */
  /* log_info (_("searching for \"%s\" from %s\n"), searchstr,
   * keyserver->uri);
   */

  parm.ctrl = ctrl;
  std::string disp = utf8_to_native(searchstr.c_str(), searchstr.size(), 0);
  parm.searchstr_disp = xstrdup(disp.c_str());

  err = gpg_dirmngr_ks_search(ctrl, searchstr.c_str(), search_line_handler,
                              &parm);

  if (parm.not_found) {
    if (parm.searchstr_disp)
      log_info(_("key \"%s\" not found on keyserver\n"), parm.searchstr_disp);
    else
      log_info(_("key not found on keyserver\n"));
  }

  if (err == GPG_ERR_NO_KEYSERVER)
    log_error(_("no keyserver known (use option --keyserver)\n"));
  else if (err)
    log_error("error searching keyserver: %s\n", gpg_strerror(err));

/* switch(ret) */
/*   { */
/*   case KEYSERVER_SCHEME_NOT_FOUND: */
/*     log_error(_("no handler for keyserver scheme '%s'\n"), */
/*   	    opt.keyserver->scheme); */
/*     break; */

/*   case KEYSERVER_NOT_SUPPORTED: */
/*     log_error(_("action '%s' not supported with keyserver " */
/*   	      "scheme '%s'\n"), "search", opt.keyserver->scheme); */
/*     break; */

/*   case KEYSERVER_TIMEOUT: */
/*     log_error(_("keyserver timed out\n")); */
/*     break; */

/*   case KEYSERVER_INTERNAL_ERROR: */
/*   default: */
/*     log_error(_("keyserver internal error\n")); */
/*     break; */
/*   } */

/* return GPG_ERR_KEYSERVER; */

leave:
  xfree(parm.desc);
  xfree(parm.searchstr_disp);

  return err;
}

/* Helper for keyserver_get.  Here we only receive a chunk of the
   description to be processed in one batch.  This is required due to
   the limited number of patterns the dirmngr interface (KS_GET) can
   grok and to limit the amount of temporary required memory.  */
static gpg_error_t keyserver_get_chunk(
    ctrl_t ctrl, KEYDB_SEARCH_DESC *desc, int ndesc, int *r_ndesc_used,
    import_stats_t stats_handle, struct keyserver_spec *override_keyserver,
    int quick, unsigned char **r_fpr, size_t *r_fprlen)

{
  gpg_error_t err = 0;
  char **pattern;
  int idx, npat;
  estream_t datastream;
  char *source = NULL;
  size_t linelen; /* Estimated linelen for KS_GET.  */
  size_t n;

#define MAX_KS_GET_LINELEN 950 /* Somewhat lower than the real limit.  */

  *r_ndesc_used = 0;

  /* Create an array filled with a search pattern for each key.  The
     array is delimited by a NULL entry.  */
  pattern = (char **)xtrycalloc(ndesc + 1, sizeof *pattern);
  if (!pattern) return gpg_error_from_syserror();

  /* Note that we break the loop as soon as our estimation of the to
     be used line length reaches the limit.  But we do this only if we
     have processed at least one search requests so that an overlong
     single request will be rejected only later by gpg_dirmngr_ks_get
     but we are sure that R_NDESC_USED has been updated.  This avoids
     a possible indefinite loop.  */
  linelen = 17; /* "KS_GET --quick --" */
  for (npat = idx = 0; idx < ndesc; idx++) {
    int quiet = 0;

    if (desc[idx].mode == KEYDB_SEARCH_MODE_FPR20 ||
        desc[idx].mode == KEYDB_SEARCH_MODE_FPR16) {
      n = 1 + 2 + 2 * 20;
      if (idx && linelen + n > MAX_KS_GET_LINELEN)
        break; /* Declare end of this chunk.  */
      linelen += n;

      pattern[npat] = (char *)xtrymalloc(n);
      if (!pattern[npat])
        err = gpg_error_from_syserror();
      else {
        strcpy(pattern[npat], "0x");
        bin2hex(desc[idx].u.fpr,
                desc[idx].mode == KEYDB_SEARCH_MODE_FPR20 ? 20 : 16,
                pattern[npat] + 2);
        npat++;
      }
    } else if (desc[idx].mode == KEYDB_SEARCH_MODE_LONG_KID) {
      n = 1 + 2 + 16;
      if (idx && linelen + n > MAX_KS_GET_LINELEN)
        break; /* Declare end of this chunk.  */
      linelen += n;

      pattern[npat] =
          xtryasprintf("0x%08lX%08lX", (unsigned long)desc[idx].u.kid[0],
                       (unsigned long)desc[idx].u.kid[1]);
      if (!pattern[npat])
        err = gpg_error_from_syserror();
      else
        npat++;
    } else if (desc[idx].mode == KEYDB_SEARCH_MODE_SHORT_KID) {
      n = 1 + 2 + 8;
      if (idx && linelen + n > MAX_KS_GET_LINELEN)
        break; /* Declare end of this chunk.  */
      linelen += n;

      pattern[npat] =
          xtryasprintf("0x%08lX", (unsigned long)desc[idx].u.kid[1]);
      if (!pattern[npat])
        err = gpg_error_from_syserror();
      else
        npat++;
    } else if (desc[idx].mode == KEYDB_SEARCH_MODE_EXACT) {
      /* The Dirmngr also uses classify_user_id to detect the type
         of the search string.  By adding the '=' prefix we force
         Dirmngr's KS_GET to consider this an exact search string.
         (In gpg 1.4 and gpg 2.0 the keyserver helpers used the
         KS_GETNAME command to indicate this.)  */

      n = 1 + 1 + strlen(desc[idx].u.name);
      if (idx && linelen + n > MAX_KS_GET_LINELEN)
        break; /* Declare end of this chunk.  */
      linelen += n;

      pattern[npat] = strconcat("=", desc[idx].u.name, NULL);
      if (!pattern[npat])
        err = gpg_error_from_syserror();
      else {
        npat++;
        quiet = 1;
      }
    } else if (desc[idx].mode == KEYDB_SEARCH_MODE_NONE)
      continue;
    else
      BUG();

    if (err) {
      for (idx = 0; idx < npat; idx++) xfree(pattern[idx]);
      xfree(pattern);
      return err;
    }

    if (!quiet && override_keyserver) {
      if (!override_keyserver->uri.host.empty())
        log_info(_("requesting key %s from %s server %s\n"),
                 keystr_from_desc(&desc[idx]),
                 override_keyserver->uri.scheme.c_str(),
                 override_keyserver->uri.host.c_str());
      else {
        std::string uri = override_keyserver->uri.str();
        log_info(_("requesting key %s from %s\n"), keystr_from_desc(&desc[idx]),
                 uri.c_str());
      }
    }
  }

  /* Remember now many of search items were considered.  Note that
     this is different from NPAT.  */
  *r_ndesc_used = idx;

  err = gpg_dirmngr_ks_get(ctrl, pattern, override_keyserver, quick,
                           &datastream, &source);
  for (idx = 0; idx < npat; idx++) xfree(pattern[idx]);
  xfree(pattern);
  if (opt.verbose && source) log_info("data source: %s\n", source);

  if (!err) {
    struct ks_retrieval_screener_arg_s screenerarg;

    /* FIXME: Check whether this comment should be moved to dirmngr.

       Slurp up all the key data.  In the future, it might be nice
       to look for KEY foo OUTOFBAND and FAILED indicators.  It's
       harmless to ignore them, but ignoring them does make gpg
       complain about "no valid OpenPGP data found".  One way to do
       this could be to continue parsing this line-by-line and make
       a temp iobuf for each key.  Note that we don't allow the
       import of secret keys from a keyserver.  Keyservers should
       never accept or send them but we better protect against rogue
       keyservers. */

    screenerarg.desc = desc;
    screenerarg.ndesc = *r_ndesc_used;
    import_keys_es_stream(
        ctrl, datastream, stats_handle, r_fpr, r_fprlen,
        (opt.keyserver_options.import_options | IMPORT_NO_SECKEY),
        keyserver_retrieval_screener, &screenerarg);
  }
  es_fclose(datastream);
  xfree(source);

  return err;
}

/* Retrieve a key from a keyserver.  The search pattern are in
   (DESC,NDESC).  Allowed search modes are keyid, fingerprint, and
   exact searches.  OVERRIDE_KEYSERVER gives an optional override
   keyserver. If (R_FPR,R_FPRLEN) are not NULL, they may return the
   fingerprint of a single imported key.  If QUICK is set, dirmngr is
   advised to use a shorter timeout. */
static gpg_error_t keyserver_get(ctrl_t ctrl, KEYDB_SEARCH_DESC *desc,
                                 int ndesc,
                                 struct keyserver_spec *override_keyserver,
                                 int quick, unsigned char **r_fpr,
                                 size_t *r_fprlen) {
  gpg_error_t err;
  import_stats_t stats_handle;
  int ndesc_used;
  int any_good = 0;

  stats_handle = import_new_stats_handle();

  for (;;) {
    err = keyserver_get_chunk(ctrl, desc, ndesc, &ndesc_used, stats_handle,
                              override_keyserver, quick, r_fpr, r_fprlen);
    if (!err) any_good = 1;
    if (err || ndesc_used >= ndesc) break; /* Error or all processed.  */
    /* Prepare for the next chunk.  */
    desc += ndesc_used;
    ndesc -= ndesc_used;
  }

  if (any_good) import_print_stats(stats_handle);

  import_release_stats_handle(stats_handle);
  return err;
}

/* Send all keys specified by KEYSPECS to the configured keyserver.  */
static gpg_error_t keyserver_put(ctrl_t ctrl,
                                 const std::vector<std::string> &keyspecs)

{
  gpg_error_t err;
  char *ksurl;

  if (keyspecs.empty()) return 0; /* Return success if the list is empty.  */

  if (gpg_dirmngr_ks_list(ctrl, &ksurl)) {
    log_error(_("no keyserver known\n"));
    return GPG_ERR_NO_KEYSERVER;
  }

  for (auto &kspec : keyspecs) {
    void *data;
    size_t datalen;
    kbnode_t keyblock;

    err = export_pubkey_buffer(ctrl, kspec.c_str(),
                               opt.keyserver_options.export_options, NULL,
                               &keyblock, &data, &datalen);
    if (err)
      log_error(_("skipped \"%s\": %s\n"), kspec.c_str(), gpg_strerror(err));
    else {
      log_info(_("sending key %s to %s\n"),
               keystr(keyblock->pkt->pkt.public_key->keyid),
               ksurl ? ksurl : "[?]");

      err = gpg_dirmngr_ks_put(ctrl, data, datalen, keyblock);
      release_kbnode(keyblock);
      xfree(data);
      if (err) {
        write_status_error("keyserver_send", err);
        log_error(_("keyserver send failed: %s\n"), gpg_strerror(err));
      }
    }
  }

  xfree(ksurl);

  return err;
}

/* Loop over all URLs in STRLIST and fetch the key at that URL.  Note
   that the fetch operation ignores the configured keyservers and
   instead directly retrieves the keys.  */
int keyserver_fetch(ctrl_t ctrl, const std::vector<std::string> &urilist) {
  gpg_error_t err;
  estream_t datastream;
  unsigned int save_options = opt.keyserver_options.import_options;

  /* Switch on fast-import, since fetch can handle more than one
     import and we don't want each set to rebuild the trustdb.
     Instead we do it once at the end. */
  opt.keyserver_options.import_options |= IMPORT_FAST;

  for (auto &sl : urilist) {
    if (!opt.quiet) log_info(_("requesting key from '%s'\n"), sl.c_str());

    err = gpg_dirmngr_ks_fetch(ctrl, sl.c_str(), &datastream);
    if (!err) {
      import_stats_t stats_handle;

      stats_handle = import_new_stats_handle();
      import_keys_es_stream(ctrl, datastream, stats_handle, NULL, NULL,
                            opt.keyserver_options.import_options, NULL, NULL);

      import_print_stats(stats_handle);
      import_release_stats_handle(stats_handle);
    } else
      log_info(_("WARNING: unable to fetch URI %s: %s\n"), sl.c_str(),
               gpg_strerror(err));
    es_fclose(datastream);
  }

  opt.keyserver_options.import_options = save_options;

  /* If the original options didn't have fast import, and the trustdb
     is dirty, rebuild. */
  if (!(opt.keyserver_options.import_options & IMPORT_FAST))
    check_or_update_trustdb(ctrl);

  return 0;
}

/* Import a key by name using LDAP */
int keyserver_import_ldap(ctrl_t ctrl, const char *name, unsigned char **fpr,
                          size_t *fprlen) {
  (void)ctrl;
  (void)name;
  (void)fpr;
  (void)fprlen;
  return GPG_ERR_NOT_IMPLEMENTED; /*FIXME*/
#if 0
  char *domain;
  struct keyserver_spec *keyserver;
  int rc,hostlen=1;
  struct srventry *srvlist=NULL;
  int srvcount,i;
  char srvname[MAXDNAME];

  /* Parse out the domain */
  domain=strrchr(name,'@');
  if(!domain)
    return GPG_ERR_GENERAL;

  domain++;

  keyserver=xmalloc_clear(sizeof(struct keyserver_spec));
  keyserver->scheme=xstrdup("ldap");
  keyserver->host=xmalloc(1);
  keyserver->host[0]='\0';

  snprintf(srvname,MAXDNAME,"_pgpkey-ldap._tcp.%s",domain);

  FIXME("network related - move to dirmngr or drop the code");
  srvcount=getsrv(srvname,&srvlist);

  for(i=0;i<srvcount;i++)
    {
      hostlen+=strlen(srvlist[i].target)+1;
      keyserver->host=xrealloc(keyserver->host,hostlen);

      strcat(keyserver->host,srvlist[i].target);

      if(srvlist[i].port!=389)
	{
	  char port[7];

	  hostlen+=6; /* a colon, plus 5 digits (unsigned 16-bit value) */
	  keyserver->host=xrealloc(keyserver->host,hostlen);

	  snprintf(port,7,":%u",srvlist[i].port);
	  strcat(keyserver->host,port);
	}

      strcat(keyserver->host," ");
    }

  free(srvlist);

  /* If all else fails, do the PGP Universal trick of
     ldap://keys.(domain) */

  hostlen+=5+strlen(domain);
  keyserver->host=xrealloc(keyserver->host,hostlen);
  strcat(keyserver->host,"keys.");
  strcat(keyserver->host,domain);

  append_to_strlist(&list,name);

  rc = GPG_ERR_NOT_IMPLEMENTED; /*FIXME*/
       /* keyserver_work (ctrl, KS_GETNAME, list, NULL, */
       /*                 0, fpr, fpr_len, keyserver); */

  free_strlist(list);

  delete keyserver;

  return rc;
#endif
}
