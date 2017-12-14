/* dns-stuff.c - DNS related code including CERT RR (rfc-4398)
 * Copyright (C) 2003, 2005, 2006, 2009 Free Software Foundation, Inc.
 * Copyright (C) 2005, 2006, 2009, 2015. 2016 Werner Koch
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

#include <stdlib.h>
#include <string.h>

#include "dns-stuff.h"

/* Check whether NAME is an IP address.  Returns a true if it is
 * either an IPv6 or a IPv4 numerical address.  The actual return
 * values can also be used to identify whether it is v4 or v6: The
 * true value will surprisingly be 4 for IPv4 and 6 for IPv6.  */
int is_ip_address(const char *name) {
  const char *s;
  int ndots, dblcol, n;

  if (*name == '[')
    return 6; /* yes: A legal DNS name may not contain this character;
                 this must be bracketed v6 address.  */
  if (*name == '.')
    return 0; /* No.  A leading dot is not a valid IP address.  */

  /* Check whether this is a v6 address.  */
  ndots = n = dblcol = 0;
  for (s = name; *s; s++) {
    if (*s == ':') {
      ndots++;
      if (s[1] == ':') {
        ndots++;
        if (dblcol) return 0; /* No: Only one "::" allowed.  */
        dblcol++;
        if (s[1]) s++;
      }
      n = 0;
    } else if (*s == '.')
      goto legacy;
    else if (!strchr("0123456789abcdefABCDEF", *s))
      return 0; /* No: Not a hex digit.  */
    else if (++n > 4)
      return 0; /* To many digits in a group.  */
  }
  if (ndots > 7)
    return 0; /* No: Too many colons.  */
  else if (ndots > 1)
    return 6; /* Yes: At least 2 colons indicate an v6 address.  */

legacy:
  /* Check whether it is legacy IP address.  */
  ndots = n = 0;
  for (s = name; *s; s++) {
    if (*s == '.') {
      if (s[1] == '.') return 0;       /* No:  Double dot. */
      if (atoi(s + 1) > 255) return 0; /* No:  Ipv4 byte value too large.  */
      ndots++;
      n = 0;
    } else if (!strchr("0123456789", *s))
      return 0; /* No: Not a digit.  */
    else if (++n > 3)
      return 0; /* No: More than 3 digits.  */
  }
  return (ndots == 3) ? 4 : 0;
}
