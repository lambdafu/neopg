/* ks-engine.h - Keyserver engines definitions
 * Copyright (C) 2011 Free Software Foundation, Inc.
 * Copyright (C) 2015  g10 Code GmbH
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

#ifndef DIRMNGR_KS_ENGINE_H
#define DIRMNGR_KS_ENGINE_H 1

#include "http.h"

/*-- ks-action.c --*/
gpg_error_t ks_print_help(ctrl_t ctrl, const char *text);
gpg_error_t ks_printf_help(ctrl_t ctrl, const char *format, ...)
    GPGRT_ATTR_PRINTF(2, 3);

/*-- ks-engine-hkp.c --*/
gpg_error_t ks_hkp_help(ctrl_t ctrl, parsed_uri_t uri);
gpg_error_t ks_hkp_search(ctrl_t ctrl, parsed_uri_t uri, const char *pattern,
                          std::string &response, unsigned int *r_http_status);
gpg_error_t ks_hkp_get(ctrl_t ctrl, parsed_uri_t uri, const char *keyspec,
                       std::string &response);
gpg_error_t ks_hkp_put(ctrl_t ctrl, parsed_uri_t uri, const void *data,
                       size_t datalen);

/*-- ks-engine-http.c --*/
gpg_error_t ks_http_help(ctrl_t ctrl, parsed_uri_t uri);
gpg_error_t ks_http_fetch(ctrl_t ctrl, const char *url, std::string &response);

#endif /*DIRMNGR_KS_ENGINE_H*/
