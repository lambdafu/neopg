/* ks-engine-http.c - HTTP OpenPGP key access
 * Copyright (C) 2011 Free Software Foundation, Inc.
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

#include <neopg/proto/http.h>

#include "dirmngr.h"
#include "ks-engine.h"
#include "misc.h"

/* Print a help output for the schemata supported by this module. */
gpg_error_t ks_http_help(ctrl_t ctrl, parsed_uri_t uri) {
  const char data[] =
      "Handler for HTTP URLs:\n"
      "  http://\n"
      "  https://\n"
      "Supported methods: fetch\n";
  gpg_error_t err;

  const char data2[] = "  http\n  https";

  if (!uri)
    err = ks_print_help(ctrl, data2);
  else if (uri->is_http && strcmp(uri->scheme, "hkp"))
    err = ks_print_help(ctrl, data);
  else
    err = 0;

  return err;
}

/* Get the key from URL which is expected to specify a http style
   scheme.  On success R_FP has an open stream to read the data.  */
gpg_error_t ks_http_fetch(ctrl_t ctrl, const char *url, std::string &response) {
  if (!url) return GPG_ERR_INV_ARG;

  if (opt.disable_http) {
    log_error(_("CRL access not possible due to disabled %s\n"), "HTTP");
    return GPG_ERR_NOT_SUPPORTED;
  }
  /* libcurl doesn't support disabling all DNS lookups.  */
  if (opt.disable_ipv4 && opt.disable_ipv6) {
    log_error(_("CRL access not possible due to disabled %s\n"),
              "ipv4 and ipv6");
    return GPG_ERR_NOT_SUPPORTED;
  }

  /* Note that we only use the system provided certificates.  */
  /* ctrl->http_no_crl support?  */
  NeoPG::Proto::Http request;
  request.set_url(url).forbid_reuse().set_timeout(ctrl->timeout).no_cache();

  if (opt.http_proxy)
    request.set_proxy(opt.http_proxy);
  else
    request.default_proxy(opt.honor_http_proxy);

  if (opt.disable_ipv6)
    request.set_ipresolve(NeoPG::Proto::Http::Resolve::IPv4);
  else if (opt.disable_ipv4)
    request.set_ipresolve(NeoPG::Proto::Http::Resolve::IPv6);

  try {
    response = request.fetch();
  } catch (const std::runtime_error &e) {
    log_error(_("error retrieving '%s': %s\n"), url, e.what());
    return GPG_ERR_NO_DATA;
  }

  return 0;
}
