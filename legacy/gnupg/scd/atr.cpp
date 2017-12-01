/* atr.c - ISO 7816 ATR functions
 * Copyright (C) 2003, 2011 Free Software Foundation, Inc.
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

#include <boost/format.hpp>
#include <sstream>

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <gpg-error.h>
#include "../common/logging.h"
#include "../common/util.h"
#include "atr.h"

static int const fi_table[16] = {0,  372, 558, 744,  1116, 1488, 1860, -1,
                                 -1, 512, 768, 1024, 1536, 2048, -1,   -1};
static int const di_table[16] = {-1, 1,  2,  4,  8,  16,  -1,  -1,
                                 0,  -1, -2, -4, -8, -16, -32, -64};

/* Dump the ATR in (BUFFER,BUFLEN) to a human readable format and
   return that as a malloced buffer.  The caller must release this
   buffer using es_free!  On error this function returns NULL and sets
   ERRNO.  */
char *atr_dump(const void *buffer, size_t buflen) {
  const unsigned char *atr = (const unsigned char *)buffer;
  size_t atrlen = buflen;
  std::stringstream fp;
  int have_ta, have_tb, have_tc, have_td;
  int n_historical;
  int idx, val;
  unsigned char chksum;
  char *result;

  if (!atrlen) {
    fp << "error: empty ATR\n";
    goto bailout;
  }

  for (idx = 0; idx < atrlen; idx++)
    fp << boost::format("%s%02X") % (idx ? " " : "") % atr[idx];
  fp << '\n';

  if (*atr == 0x3b)
    fp << "Direct convention\n";
  else if (*atr == 0x3f)
    fp << "Inverse convention\n";
  else
    fp << boost::format("error: invalid TS character 0x%02x\n") % *atr;
  if (!--atrlen) goto bailout;
  atr++;

  chksum = *atr;
  for (idx = 1; idx < atrlen - 1; idx++) chksum ^= atr[idx];

  have_ta = !!(*atr & 0x10);
  have_tb = !!(*atr & 0x20);
  have_tc = !!(*atr & 0x40);
  have_td = !!(*atr & 0x80);
  n_historical = (*atr & 0x0f);
  fp << n_historical << " historical characters indicated\n";

  if (have_ta + have_tb + have_tc + have_td + n_historical > atrlen)
    fp << "error: ATR shorter than indicated by format character\n";
  if (!--atrlen) goto bailout;
  atr++;

  if (have_ta) {
    fp << "TA1: F=";
    val = fi_table[(*atr >> 4) & 0x0f];
    if (!val)
      fp << "internal clock";
    else if (val == -1)
      fp << "RFU";
    else
      fp << val;
    fp << " D=";
    val = di_table[*atr & 0x0f];
    if (!val)
      fp << "[impossible value]\n";
    else if (val == -1)
      fp << "RFU\n";
    else if (val < 0)
      fp << "1/" << val << "\n";
    else
      fp << val << "\n";

    if (!--atrlen) goto bailout;
    atr++;
  }

  if (have_tb) {
    fp << boost::format("TB1: II=%d PI1=%d%s\n") % ((*atr >> 5) & 3) %
              (*atr & 0x1f) % ((*atr & 0x80) ? " [high bit not cleared]" : "");
    if (!--atrlen) goto bailout;
    atr++;
  }

  if (have_tc) {
    if (*atr == 255)
      fp << "TC1: guard time shortened to 1 etu\n";
    else
      fp << boost::format("TC1: (extra guard time) N=%d\n") % ((int)*atr);

    if (!--atrlen) goto bailout;
    atr++;
  }

  if (have_td) {
    have_ta = !!(*atr & 0x10);
    have_tb = !!(*atr & 0x20);
    have_tc = !!(*atr & 0x40);
    have_td = !!(*atr & 0x80);
    fp << boost::format("TD1: protocol T%d supported\n") % ((int)(*atr & 0x0f));

    if (have_ta + have_tb + have_tc + have_td + n_historical > atrlen)
      fp << "error: ATR shorter than indicated by format character\n";

    if (!--atrlen) goto bailout;
    atr++;
  } else
    have_ta = have_tb = have_tc = have_td = 0;

  if (have_ta) {
    fp << boost::format("TA2: (PTS) %stoggle, %splicit, T=%02X\n") %
              ((*atr & 0x80) ? "no-" : "") % ((*atr & 0x10) ? "im" : "ex") %
              (*atr & 0x0f);
    if ((*atr & 0x60))
      fp << boost::format("note: reserved bits are set (TA2=0x%02X)\n") % *atr;
    if (!--atrlen) goto bailout;
    atr++;
  }

  if (have_tb) {
    fp << boost::format("TB2: PI2=%d\n") % *atr;
    if (!--atrlen) goto bailout;
    atr++;
  }

  if (have_tc) {
    fp << boost::format("TC2: PWI=%d\n") % *atr;
    if (!--atrlen) goto bailout;
    atr++;
  }

  if (have_td) {
    have_ta = !!(*atr & 0x10);
    have_tb = !!(*atr & 0x20);
    have_tc = !!(*atr & 0x40);
    have_td = !!(*atr & 0x80);
    fp << boost::format("TD2: protocol T%d supported\n") % (*atr & 0x0f);

    if (have_ta + have_tb + have_tc + have_td + n_historical > atrlen)
      fp << "error: ATR shorter than indicated by format character\n";

    if (!--atrlen) goto bailout;
    atr++;
  } else
    have_ta = have_tb = have_tc = have_td = 0;

  for (idx = 3; have_ta || have_tb || have_tc || have_td; idx++) {
    if (have_ta) {
      fp << boost::format("TA%d: IFSC=%d\n") % idx % ((int)*atr);
      if (!--atrlen) goto bailout;
      atr++;
    }

    if (have_tb) {
      fp << boost::format("TB%d: BWI=%d CWI=%d\n") % idx %
                ((int)(*atr >> 4) & 0x0f) % ((int)(*atr & 0x0f));
      if (!--atrlen) goto bailout;
      atr++;
    }

    if (have_tc) {
      fp << boost::format("TC%d: 0x%02X\n") % idx % *atr;
      if (!--atrlen) goto bailout;
      atr++;
    }

    if (have_td) {
      have_ta = !!(*atr & 0x10);
      have_tb = !!(*atr & 0x20);
      have_tc = !!(*atr & 0x40);
      have_td = !!(*atr & 0x80);
      fp << boost::format("TD%d: protocol T%d supported\n") % idx %
                ((int)(*atr & 0x0f));

      if (have_ta + have_tb + have_tc + have_td + n_historical > atrlen)
        fp << "error: ATR shorter than indicated by format character\n";

      if (!--atrlen) goto bailout;
      atr++;
    } else
      have_ta = have_tb = have_tc = have_td = 0;
  }

  if (n_historical + 1 > atrlen)
    fp << "error: ATR shorter than required for historical bytes and "
          "checksum\n";

  if (n_historical) {
    fp << "HCH:";
    for (; n_historical && atrlen; n_historical--, atrlen--, atr++)
      fp << boost::format(" %02X") % *atr;
    fp << '\n';
  }

  if (!atrlen)
    fp << "error: checksum missing\n";
  else if (*atr == chksum)
    fp << boost::format("TCK: %02X (good)\n") % *atr;
  else
    fp << boost::format("TCK: %02X (bad; computed %02X)\n") % *atr % chksum;

  atrlen--;
  if (atrlen)
    fp << boost::format("error: %u bytes garbage at end of ATR\n") %
              (unsigned int)atrlen;

bailout:
  return xstrdup(fp.str().c_str());
}
