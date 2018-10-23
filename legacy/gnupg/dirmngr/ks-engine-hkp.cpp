/* ks-engine-hkp.c - HKP keyserver engine
 * Copyright (C) 2011, 2012 Free Software Foundation, Inc.
 * Copyright (C) 2011, 2012, 2014 Werner Koch
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

#include <tao/json/external/optional.hpp>

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <neopg/proto/http.h>

#include "../common/userids.h"
#include "dirmngr.h"
#include "dns-stuff.h"
#include "ks-engine.h"
#include "misc.h"

/* To match the behaviour of our old gpgkeys helper code we escape
   more characters than actually needed. */
#define EXTRA_ESCAPE_CHARS "@!\"#$%&'()*+,-./:;<=>?[\\]^_{|}~"

/* Print a help output for the schemata supported by this module. */
gpg_error_t ks_hkp_help(ctrl_t ctrl, parsed_uri_t uri) {
  const char data[] =
      "Handler for HKP URLs:\n"
      "  hkp://\n"
      "  hkps://\n"
      "Supported methods: search, get, put\n";
  gpg_error_t err;

  const char data2[] = "  hkp\n  hkps";

  if (!uri)
    err = ks_print_help(ctrl, data2);
  else if (uri->is_http &&
           (!strcmp(uri->scheme, "hkp") || !strcmp(uri->scheme, "hkps")))
    err = ks_print_help(ctrl, data);
  else
    err = 0;

  return err;
}

/* Build the remote part of the URL from SCHEME, HOST and an optional
 * PORT.  Returns an allocated string at R_HOSTPORT or NULL on
 * failure.  */
static std::string make_host_part(ctrl_t ctrl, const std::string &scheme,
                                  const std::string &hostname,
                                  unsigned short port) {
  std::string hostport;

  if (scheme == "hkps" || scheme == "https")
    hostport += "https://";
  else
    hostport += "http://";

  if (hostname[0] != '[' && is_ip_address(hostname.c_str()) == 6)
    hostport += "[" + hostname + "]";
  else
    hostport += hostname;

  if (!port) {
    if (scheme == "443")
      port = 443;
    else
      port = 11371;
  }
  hostport += ":" + std::to_string(port);
  return hostport;
}

/* Send an HTTP request.  On success returns response in RESPONSE.  If
   POST_CB is not NULL a post request is used and that callback is
   called to allow writing the post data.  If R_HTTP_STATUS is not
   NULL, the http status code will be stored there.  */
static gpg_error_t send_request(ctrl_t ctrl, const std::string &url,
                                tao::optional<std::string> post_data,
                                std::string &response,
                                unsigned int *r_http_status) {
  if (url.empty()) return GPG_ERR_INV_ARG;

  if (opt.disable_http) {
    log_error(_("CRL access not possible due to disabled %s\n"), "HTTP");
    return GPG_ERR_NOT_SUPPORTED;
  }
  /* libcurl doesn't easily support disabling all DNS lookups.  */
  if (opt.disable_ipv4 && opt.disable_ipv6) {
    log_error(_("CRL access not possible due to disabled %s\n"),
              "ipv4 and ipv6");
    return GPG_ERR_NOT_SUPPORTED;
  }

  NeoPG::Http request;
  request.set_url(url).forbid_reuse().set_timeout(ctrl->timeout).no_cache();

  if (opt.http_proxy)
    request.set_proxy(opt.http_proxy);
  else
    request.default_proxy(opt.honor_http_proxy);

  if (opt.disable_ipv6)
    request.set_ipresolve(NeoPG::Http::Resolve::IPv4);
  else if (opt.disable_ipv4)
    request.set_ipresolve(NeoPG::Http::Resolve::IPv6);

  if (post_data) /* x-www-form-urlencoded is default */
    request.set_post(post_data);

  /* SSL Config.  It all boils down to a simple switch: Normally, we
     use the system CA list.  And for the SKS Poolserver, we take a
     baked in CA.  */
  NeoPG::URI uri(url);
  if (uri.host == "hkps.pool.sks-keyservers.net") {
    char *pemname =
        make_filename_try(gnupg_datadir(), "sks-keyservers.netCA.pem", NULL);
    request.set_cainfo(pemname);
  }

  try {
    response = request.fetch();
    /* FIXMEFIXMEFIXME: Return http status in r_http_status.  */
  } catch (const std::runtime_error &e) {
    log_error(_("error retrieving '%s': %s\n"), url.c_str(), e.what());
    return GPG_ERR_NO_DATA;
  }

  return 0;
}

/* Search the keyserver identified by URI for keys matching PATTERN.
   On success, data is in RESPONSE.  If R_HTTP_STATUS is not NULL, the
   http status code will be stored there.  */
gpg_error_t ks_hkp_search(ctrl_t ctrl, parsed_uri_t uri, const char *pattern,
                          std::string &response, unsigned int *r_http_status) {
  gpg_error_t err;
  KEYDB_SEARCH_DESC desc;
  char fprbuf[2 + 40 + 1];
  std::string hostport;
  std::string request;

  /* Remove search type indicator and adjust PATTERN accordingly.
     Note that HKP keyservers like the 0x to be present when searching
     by keyid.  We need to re-format the fingerprint and keyids so to
     remove the gpg specific force-use-of-this-key flag ("!").  */
  err = classify_user_id(pattern, &desc, 1);
  if (err) return err;
  switch (desc.mode) {
    case KEYDB_SEARCH_MODE_EXACT:
    case KEYDB_SEARCH_MODE_SUBSTR:
    case KEYDB_SEARCH_MODE_MAIL:
    case KEYDB_SEARCH_MODE_MAILSUB:
      pattern = desc.u.name;
      break;
    case KEYDB_SEARCH_MODE_SHORT_KID:
      snprintf(fprbuf, sizeof fprbuf, "0x%08lX", (unsigned long)desc.u.kid[1]);
      pattern = fprbuf;
      break;
    case KEYDB_SEARCH_MODE_LONG_KID:
      snprintf(fprbuf, sizeof fprbuf, "0x%08lX%08lX",
               (unsigned long)desc.u.kid[0], (unsigned long)desc.u.kid[1]);
      pattern = fprbuf;
      break;
    case KEYDB_SEARCH_MODE_FPR16:
      fprbuf[0] = '0';
      fprbuf[1] = 'x';
      bin2hex(desc.u.fpr, 16, fprbuf + 2);
      pattern = fprbuf;
      break;
    case KEYDB_SEARCH_MODE_FPR20:
    case KEYDB_SEARCH_MODE_FPR:
      fprbuf[0] = '0';
      fprbuf[1] = 'x';
      bin2hex(desc.u.fpr, 20, fprbuf + 2);
      pattern = fprbuf;
      break;
    default:
      return GPG_ERR_INV_USER_ID;
  }

  /* Build the request string.  */
  std::string searchkey;

  hostport = make_host_part(ctrl, uri->scheme, uri->host, uri->port);
  searchkey = http_escape_string(pattern, EXTRA_ESCAPE_CHARS);
  request = hostport + "/pks/lookup?op=index&options=mr&search=" + searchkey;

  /* Send the request.  */
  response.clear();
  err = send_request(ctrl, request, tao::nullopt, response, r_http_status);
  if (err) return err;

  err = dirmngr_status(ctrl, "SOURCE", hostport.c_str(), NULL);
  if (err) return err;

  /* Peek at the response.  */
  if (response.size() == 0)
    return GPG_ERR_EOF;
  else if (response[0] == '<')
    /* The document begins with a '<': Assume a HTML response,
       which we don't support.  */
    return GPG_ERR_UNSUPPORTED_ENCODING;

  return 0;
}

/* Get the key described key the KEYSPEC string from the keyserver
   identified by URI.  On success data is in RESPONSE.  The data will
   be provided in a format GnuPG can import (either a binary OpenPGP
   message or an armored one).  */
gpg_error_t ks_hkp_get(ctrl_t ctrl, parsed_uri_t uri, const char *keyspec,
                       std::string &response) {
  gpg_error_t err;
  KEYDB_SEARCH_DESC desc;
  char kidbuf[2 + 40 + 1];
  const char *exactname = NULL;
  std::string searchkey;
  std::string hostport;
  std::string request;

  /* Remove search type indicator and adjust PATTERN accordingly.
     Note that HKP keyservers like the 0x to be present when searching
     by keyid.  We need to re-format the fingerprint and keyids so to
     remove the gpg specific force-use-of-this-key flag ("!").  */
  err = classify_user_id(keyspec, &desc, 1);
  if (err) return err;
  switch (desc.mode) {
    case KEYDB_SEARCH_MODE_SHORT_KID:
      snprintf(kidbuf, sizeof kidbuf, "0x%08lX", (unsigned long)desc.u.kid[1]);
      break;
    case KEYDB_SEARCH_MODE_LONG_KID:
      snprintf(kidbuf, sizeof kidbuf, "0x%08lX%08lX",
               (unsigned long)desc.u.kid[0], (unsigned long)desc.u.kid[1]);
      break;
    case KEYDB_SEARCH_MODE_FPR20:
    case KEYDB_SEARCH_MODE_FPR:
      /* This is a v4 fingerprint. */
      kidbuf[0] = '0';
      kidbuf[1] = 'x';
      bin2hex(desc.u.fpr, 20, kidbuf + 2);
      break;

    case KEYDB_SEARCH_MODE_EXACT:
      exactname = desc.u.name;
      break;

    case KEYDB_SEARCH_MODE_FPR16:
      log_error("HKP keyservers do not support v3 fingerprints\n");
    /* fall through */
    default:
      return GPG_ERR_INV_USER_ID;
  }

  searchkey =
      http_escape_string(exactname ? exactname : kidbuf, EXTRA_ESCAPE_CHARS);

  /* Build the request string.  */
  hostport = make_host_part(ctrl, uri->scheme, uri->host, uri->port);
  request = hostport + "/pks/lookup?op=get&options=mr&search=" + searchkey +
            (exactname ? "&exact=on" : "");

  /* Send the request.  */
  response.clear();
  err = send_request(ctrl, request, tao::nullopt, response, NULL);
  if (err) return err;

  return dirmngr_status(ctrl, "SOURCE", hostport.c_str(), NULL);
}

/* Send the key in {DATA,DATALEN} to the keyserver identified by URI.  */
gpg_error_t ks_hkp_put(ctrl_t ctrl, parsed_uri_t uri, const void *data,
                       size_t datalen) {
  gpg_error_t err;
  std::string hostport;
  std::string request;
  char *armored = NULL;
  std::string response;
  std::string post_data;

  err = armor_data(&armored, data, datalen);
  if (err) return err;

  post_data = "keytext=";
  post_data += http_escape_string(armored, EXTRA_ESCAPE_CHARS);

  xfree(armored);

  /* Build the request string.  */
  hostport = make_host_part(ctrl, uri->scheme, uri->host, uri->port);
  request = hostport + "/pks/add";

  response.clear();
  return send_request(ctrl, request, post_data, response, NULL);
}
