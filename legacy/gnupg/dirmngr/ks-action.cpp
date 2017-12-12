/* ks-action.c - OpenPGP keyserver actions
 * Copyright (C) 2011 Free Software Foundation, Inc.
 * Copyright (C) 2011, 2014 Werner Koch
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

#include <config.h>

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dirmngr.h"
#include "ks-action.h"
#include "ks-engine.h"
#include "misc.h"

/* Called by the engine's help functions to print the actual help.  */
gpg_error_t ks_print_help(ctrl_t ctrl, const char *text) {
  return dirmngr_status_help(ctrl, text);
}

/* Called by the engine's help functions to print the actual help.  */
gpg_error_t ks_printf_help(ctrl_t ctrl, const char *format, ...) {
  va_list arg_ptr;
  gpg_error_t err;
  char *buf;

  va_start(arg_ptr, format);
  int rc = es_vasprintf(&buf, format, arg_ptr);
  err = rc >= 0 ? 0 : gpg_error_from_syserror();
  va_end(arg_ptr);
  if (!err) err = dirmngr_status_help(ctrl, buf);
  es_free(buf);
  return err;
}

/* Run the help command for the engine responsible for URI.  */
gpg_error_t ks_action_help(ctrl_t ctrl, const char *url) {
  gpg_error_t err;
  parsed_uri_t parsed_uri; /* The broken down URI.  */

  if (!url || !*url) {
    ks_print_help(ctrl, "Known schemata:\n");
    parsed_uri = NULL;
  } else {
    { err = http_parse_uri(&parsed_uri, url, 1); }

    if (err) return err;
  }

  /* Call all engines to give them a chance to print a help sting.  */
  err = ks_hkp_help(ctrl, parsed_uri);
  if (!err) err = ks_http_help(ctrl, parsed_uri);

  if (!parsed_uri)
    ks_print_help(ctrl, "(Use an URL for engine specific help.)");
  else
    http_release_parsed_uri(parsed_uri);
  return err;
}

/* Resolve all host names.  This is useful for looking at the status
   of configured keyservers.  */
gpg_error_t ks_action_resolve(ctrl_t ctrl, uri_item_t keyservers) {
  gpg_error_t err = 0;
  int any_server = 0;
  uri_item_t uri;

  for (uri = keyservers; !err && uri; uri = uri->next) {
    if (uri->parsed_uri->is_http) {
      any_server = 1;
      err = ks_hkp_resolve(ctrl, uri->parsed_uri);
      if (err) break;
    }
  }

  if (!any_server) err = GPG_ERR_NO_KEYSERVER;
  return err;
}

/* Search all configured keyservers for keys matching PATTERNS and
   write the result to the provided output stream.  */
gpg_error_t ks_action_search(ctrl_t ctrl, uri_item_t keyservers,
                             const std::vector<std::string> &patterns,
                             estream_t outfp) {
  gpg_error_t err = 0;
  int any_server = 0;
  int any_results = 0;
  uri_item_t uri;
  std::string response;

  if (patterns.empty()) return GPG_ERR_NO_USER_ID;

  /* FIXME: We only take care of the first pattern.  To fully support
     multiple patterns we might either want to run several queries in
     parallel and merge them.  We also need to decide what to do with
     errors - it might not be the best idea to ignore an error from
     one server and silently continue with another server.  For now we
     stop at the first error, unless the server responds with '404 Not
     Found', in which case we try the next server.  */
  for (uri = keyservers; !err && uri; uri = uri->next) {
    int is_http = uri->parsed_uri->is_http;
    unsigned int http_status = 0;
    if (is_http) {
      any_server = 1;
      {
        err = ks_hkp_search(ctrl, uri->parsed_uri, patterns[0].c_str(),
                            response, &http_status);
      }

      if (err == GPG_ERR_NO_DATA && http_status == 404 /* not found */) {
        /* No record found.  Clear error and try next server.  */
        err = 0;
        continue;
      }

      if (!err) {
        es_write(outfp, response.data(), response.size(), NULL);
        any_results = 1;
        break;
      }
    }
  }

  if (!any_server)
    err = GPG_ERR_NO_KEYSERVER;
  else if (err == 0 && !any_results)
    err = GPG_ERR_NO_DATA;
  return err;
}

/* Get the requested keys (matching PATTERNS) using all configured
   keyservers and write the result to the provided output stream.  */
gpg_error_t ks_action_get(ctrl_t ctrl, uri_item_t keyservers,
                          const std::vector<std::string> &patterns,
                          estream_t outfp) {
  gpg_error_t err = 0;
  gpg_error_t first_err = 0;
  int any_server = 0;
  int any_data = 0;
  uri_item_t uri;
  std::string response;

  if (patterns.empty()) return GPG_ERR_NO_USER_ID;

  /* FIXME: We only take care of the first keyserver.  To fully
     support multiple keyservers we need to track the result for each
     pattern and use the next keyserver if one key was not found.  The
     keyservers might not all be fully synced thus it is not clear
     whether the first keyserver has the freshest copy of the key.
     Need to think about a better strategy.  */
  for (uri = keyservers; !err && uri; uri = uri->next) {
    int is_http = uri->parsed_uri->is_http;

    printf("considering %s %i\n", uri->uri, is_http);

    if (is_http) {
      any_server = 1;
      for (auto &pattern : patterns) {
        {
          std::string response;
          err = ks_hkp_get(ctrl, uri->parsed_uri, pattern.c_str(), response);
          if (err) break;
        }

        if (err) {
          /* It is possible that a server does not carry a
             key, thus we only save the error and continue
             with the next pattern.  FIXME: It is an open
             question how to return such an error condition to
             the caller.  */
          first_err = err;
          err = 0;
        } else {
          es_write(outfp, response.data(), response.size(), NULL);
          any_data = 1;
        }
      }
    }
    if (any_data) break; /* Stop loop after a keyserver returned something.  */
  }

  if (!any_server)
    err = GPG_ERR_NO_KEYSERVER;
  else if (!err && first_err && !any_data)
    err = first_err;
  return err;
}

/* Retrieve keys from URL and write the result to the provided output
   stream OUTFP.  */
gpg_error_t ks_action_fetch(ctrl_t ctrl, const char *url, estream_t outfp) {
  gpg_error_t err = 0;
  std::string response;
  parsed_uri_t parsed_uri; /* The broken down URI.  */

  if (!url) return GPG_ERR_INV_URI;

  err = http_parse_uri(&parsed_uri, url, 1);
  if (err) return err;

  if (parsed_uri->is_http) {
    err = ks_http_fetch(ctrl, url, response);
    if (!err) {
      es_write(outfp, response.data(), response.size(), NULL);
    }
  } else if (!parsed_uri->opaque) {
    err = GPG_ERR_INV_URI;
  } else
    err = GPG_ERR_INV_URI;

  http_release_parsed_uri(parsed_uri);
  return err;
}

/* Send an OpenPGP key to all keyservers.  The key in {DATA,DATALEN}
   is expected to be in OpenPGP binary transport format.  The metadata
   in {INFO,INFOLEN} is in colon-separated format (concretely, it is
   the output of 'for x in keys sigs; do gpg --list-$x --with-colons
   KEYID; done'.  This function may modify DATA and INFO.  If this is
   a problem, then the caller should create a copy.  */
gpg_error_t ks_action_put(ctrl_t ctrl, uri_item_t keyservers, void *data,
                          size_t datalen, void *info, size_t infolen) {
  gpg_error_t err = 0;
  gpg_error_t first_err = 0;
  int any_server = 0;
  uri_item_t uri;

  (void)info;
  (void)infolen;

  for (uri = keyservers; !err && uri; uri = uri->next) {
    int is_http = uri->parsed_uri->is_http;

    if (is_http) {
      any_server = 1;
      { err = ks_hkp_put(ctrl, uri->parsed_uri, data, datalen); }
      if (err) {
        first_err = err;
        err = 0;
      }
    }
  }

  if (!any_server)
    err = GPG_ERR_NO_KEYSERVER;
  else if (!err && first_err)
    err = first_err;
  return err;
}
