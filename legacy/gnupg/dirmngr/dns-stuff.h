/* dns-stuff.c - DNS related code including CERT RR (rfc-4398)
 * Copyright (C) 2006 Free Software Foundation, Inc.
 * Copyright (C) 2006, 2015 Werner Koch
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
#ifndef GNUPG_DIRMNGR_DNS_STUFF_H
#define GNUPG_DIRMNGR_DNS_STUFF_H

/* Return true if NAME is a numerical IP address.  */
int is_ip_address(const char *name);

/* Return true if NAME is an onion address.  */
int is_onion_address(const char *name);

#endif /*GNUPG_DIRMNGR_DNS_STUFF_H*/
