/* http.c  -  HTTP protocol handler
 * Copyright (C) 1999, 2001, 2002, 2003, 2004, 2006, 2009, 2010,
 *               2011 Free Software Foundation, Inc.
 * Copyright (C) 2014 Werner Koch
 * Copyright (C) 2015-2017 g10 Code GmbH
 *
 * This file is part of GnuPG.
 *
 * This file is free software; you can redistribute it and/or modify
 * it under the terms of either
 *
 *   - the GNU Lesser General Public License as published by the Free
 *     Software Foundation; either version 3 of the License, or (at
 *     your option) any later version.
 *
 * or
 *
 *   - the GNU General Public License as published by the Free
 *     Software Foundation; either version 2 of the License, or (at
 *     your option) any later version.
 *
 * or both in parallel, as here.
 *
 * This file is distributed in the hope that it will be useful,
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
#include <stdlib.h>

#include "../common/util.h"
#include "dns-stuff.h"
#include "http-common.h"
#include "http.h"

#define VALID_URI_CHARS        \
  "abcdefghijklmnopqrstuvwxyz" \
  "ABCDEFGHIJKLMNOPQRSTUVWXYZ" \
  "01234567890@"               \
  "!\"#$%&'()*+,-./:;<=>?[\\]^_{|}~"

static gpg_error_t do_parse_uri(parsed_uri_t uri, int only_local_part,
                                int no_scheme_check, int force_tls);
static gpg_error_t parse_uri(parsed_uri_t *ret_uri, const char *uri,
                             int no_scheme_check, int force_tls);
static int remove_escapes(char *string);
static int insert_escapes(char *buffer, const char *string,
                          const char *special);
static uri_tuple_t parse_tuple(char *string);
static char *build_rel_path(parsed_uri_t uri);

/* Register a CA certificate for future use.  The certificate is
   expected to be in FNAME.  PEM format is assume if FNAME has a
   suffix of ".pem".  If FNAME is NULL the list of CA files is
   removed.  */

static gpg_error_t parse_uri(parsed_uri_t *ret_uri, const char *uri,
                             int no_scheme_check, int force_tls) {
  gpg_error_t ec;

  *ret_uri = (parsed_uri_t)xtrycalloc(1, sizeof **ret_uri + strlen(uri));
  if (!*ret_uri) return gpg_error_from_syserror();
  strcpy((*ret_uri)->buffer, uri);
  ec = do_parse_uri(*ret_uri, 0, no_scheme_check, force_tls);
  if (ec) {
    xfree(*ret_uri);
    *ret_uri = NULL;
  }
  return ec;
}

/*
 * Parse an URI and put the result into the newly allocated RET_URI.
 * On success the caller must use http_release_parsed_uri() to
 * releases the resources.  If NO_SCHEME_CHECK is set, the function
 * tries to parse the URL in the same way it would do for an HTTP
 * style URI.
 */
gpg_error_t http_parse_uri(parsed_uri_t *ret_uri, const char *uri,
                           int no_scheme_check) {
  return parse_uri(ret_uri, uri, no_scheme_check, 0);
}

void http_release_parsed_uri(parsed_uri_t uri) {
  if (uri) {
    uri_tuple_t r, r2;

    for (r = uri->query; r; r = r2) {
      r2 = r->next;
      xfree(r);
    }
    xfree(uri);
  }
}

static gpg_error_t do_parse_uri(parsed_uri_t uri, int only_local_part,
                                int no_scheme_check, int force_tls) {
  uri_tuple_t *tail;
  char *p, *p2, *p3, *pp;
  int n;

  p = uri->buffer;
  n = strlen(uri->buffer);

  /* Initialize all fields to an empty string or an empty list. */
  uri->scheme = uri->host = uri->path = p + n;
  uri->port = 0;
  uri->params = uri->query = NULL;
  uri->use_tls = 0;
  uri->is_http = 0;
  uri->opaque = 0;
  uri->v6lit = 0;
  uri->onion = 0;

  /* A quick validity check. */
  if (strspn(p, VALID_URI_CHARS) != n)
    return GPG_ERR_BAD_URI; /* Invalid characters found. */

  if (!only_local_part) {
    /* Find the scheme. */
    if (!(p2 = strchr(p, ':')) || p2 == p)
      return GPG_ERR_BAD_URI; /* No scheme. */
    *p2++ = 0;
    for (pp = p; *pp; pp++) *pp = tolower(*(unsigned char *)pp);
    uri->scheme = p;
    if (!strcmp(uri->scheme, "http") && !force_tls) {
      uri->port = 80;
      uri->is_http = 1;
    } else if (!strcmp(uri->scheme, "hkp") && !force_tls) {
      uri->port = 11371;
      uri->is_http = 1;
    } else if (!strcmp(uri->scheme, "https") || !strcmp(uri->scheme, "hkps") ||
               (force_tls && (!strcmp(uri->scheme, "http") ||
                              !strcmp(uri->scheme, "hkp")))) {
      uri->port = 443;
      uri->is_http = 1;
      uri->use_tls = 1;
    } else if (!no_scheme_check)
      return GPG_ERR_INV_URI; /* Unsupported scheme */

    p = p2;

    if (*p == '/' && p[1] == '/') /* There seems to be a hostname. */
    {
      p += 2;
      if ((p2 = strchr(p, '/'))) *p2++ = 0;

      /* Check for username/password encoding */
      if ((p3 = strchr(p, '@'))) {
        uri->auth = p;
        *p3++ = '\0';
        p = p3;
      }

      for (pp = p; *pp; pp++) *pp = tolower(*(unsigned char *)pp);

      /* Handle an IPv6 literal */
      if (*p == '[' && (p3 = strchr(p, ']'))) {
        *p3++ = '\0';
        /* worst case, uri->host should have length 0, points to \0 */
        uri->host = p + 1;
        uri->v6lit = 1;
        p = p3;
      } else
        uri->host = p;

      if ((p3 = strchr(p, ':'))) {
        *p3++ = '\0';
        uri->port = atoi(p3);
      }

      if ((n = remove_escapes(uri->host)) < 0) return GPG_ERR_BAD_URI;
      if (n != strlen(uri->host))
        return GPG_ERR_BAD_URI; /* Hostname includes a Nul. */
      p = p2 ? p2 : NULL;
    } else if (uri->is_http)
      return GPG_ERR_INV_URI; /* No Leading double slash for HTTP.  */
    else {
      uri->opaque = 1;
      uri->path = p;
      if (is_onion_address(uri->path)) uri->onion = 1;
      return 0;
    }

  } /* End global URI part. */

  /* Parse the pathname part if any.  */
  if (p && *p) {
    /* TODO: Here we have to check params. */

    /* Do we have a query part? */
    if ((p2 = strchr(p, '?'))) *p2++ = 0;

    uri->path = p;
    if ((n = remove_escapes(p)) < 0) return GPG_ERR_BAD_URI;
    if (n != strlen(p)) return GPG_ERR_BAD_URI; /* Path includes a Nul. */
    p = p2 ? p2 : NULL;

    /* Parse a query string if any.  */
    if (p && *p) {
      tail = &uri->query;
      for (;;) {
        uri_tuple_t elem;

        if ((p2 = strchr(p, '&'))) *p2++ = 0;
        if (!(elem = parse_tuple(p))) return GPG_ERR_BAD_URI;
        *tail = elem;
        tail = &elem->next;

        if (!p2) break; /* Ready. */
        p = p2;
      }
    }
  }

  if (is_onion_address(uri->host)) uri->onion = 1;

  return 0;
}

/*
 * Remove all %xx escapes; this is done in-place.  Returns: New length
 * of the string.
 */
static int remove_escapes(char *string) {
  int n = 0;
  unsigned char *p, *s;

  for (p = s = (unsigned char *)string; *s; s++) {
    if (*s == '%') {
      if (s[1] && s[2] && isxdigit(s[1]) && isxdigit(s[2])) {
        s++;
        *p = *s >= '0' && *s <= '9'
                 ? *s - '0'
                 : *s >= 'A' && *s <= 'F' ? *s - 'A' + 10 : *s - 'a' + 10;
        *p <<= 4;
        s++;
        *p |= *s >= '0' && *s <= '9'
                  ? *s - '0'
                  : *s >= 'A' && *s <= 'F' ? *s - 'A' + 10 : *s - 'a' + 10;
        p++;
        n++;
      } else {
        *p++ = *s++;
        if (*s) *p++ = *s++;
        if (*s) *p++ = *s++;
        if (*s) *p = 0;
        return -1; /* Bad URI. */
      }
    } else {
      *p++ = *s;
      n++;
    }
  }
  *p = 0; /* Make sure to keep a string terminator. */
  return n;
}

/* If SPECIAL is NULL this function escapes in forms mode.  */
static size_t escape_data(char *buffer, const void *data, size_t datalen,
                          const char *special) {
  int forms = !special;
  const unsigned char *s;
  size_t n = 0;

  if (forms) special = "%;?&=";

  for (s = (const unsigned char *)data; datalen; s++, datalen--) {
    if (forms && *s == ' ') {
      if (buffer) *buffer++ = '+';
      n++;
    } else if (forms && *s == '\n') {
      if (buffer) memcpy(buffer, "%0D%0A", 6);
      n += 6;
    } else if (forms && *s == '\r' && datalen > 1 && s[1] == '\n') {
      if (buffer) memcpy(buffer, "%0D%0A", 6);
      n += 6;
      s++;
      datalen--;
    } else if (strchr(VALID_URI_CHARS, *s) && !strchr(special, *s)) {
      if (buffer) *(unsigned char *)buffer++ = *s;
      n++;
    } else {
      if (buffer) {
        snprintf(buffer, 4, "%%%02X", *s);
        buffer += 3;
      }
      n += 3;
    }
  }
  return n;
}

static int insert_escapes(char *buffer, const char *string,
                          const char *special) {
  return escape_data(buffer, string, strlen(string), special);
}

/* Allocate a new string from STRING using standard HTTP escaping as
   well as escaping of characters given in SPECIALS.  A common pattern
   for SPECIALS is "%;?&=". However it depends on the needs, for
   example "+" and "/: often needs to be escaped too.  Returns NULL on
   failure and sets ERRNO.  If SPECIAL is NULL a dedicated forms
   encoding mode is used. */
std::string http_escape_string(const char *string, const char *specials) {
  int n;
  char *buf;

  n = insert_escapes(NULL, string, specials);
  buf = (char *)xtrymalloc(n + 1);
  if (buf) {
    insert_escapes(buf, string, specials);
    buf[n] = 0;
  }
  std::string result = buf;
  xfree(buf);
  return result;
}

static uri_tuple_t parse_tuple(char *string) {
  char *p = string;
  char *p2;
  int n;
  uri_tuple_t tuple;

  if ((p2 = strchr(p, '='))) *p2++ = 0;
  if ((n = remove_escapes(p)) < 0) return NULL; /* Bad URI. */
  if (n != strlen(p)) return NULL;              /* Name with a Nul in it. */
  tuple = (uri_tuple_t)xtrycalloc(1, sizeof *tuple);
  if (!tuple) return NULL; /* Out of core. */
  tuple->name = p;
  if (!p2) /* We have only the name, so we assume an empty value string. */
  {
    tuple->value = p + strlen(p);
    tuple->valuelen = 0;
    tuple->no_value = 1; /* Explicitly mark that we have seen no '='. */
  } else                 /* Name and value. */
  {
    if ((n = remove_escapes(p2)) < 0) {
      xfree(tuple);
      return NULL; /* Bad URI. */
    }
    tuple->value = p2;
    tuple->valuelen = n;
  }
  return tuple;
}
