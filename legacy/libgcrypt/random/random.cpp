/* random.c - Random number switch
 * Copyright (C) 2003, 2006, 2008, 2012  Free Software Foundation, Inc.
 *
 * This file is part of Libgcrypt.
 *
 * Libgcrypt is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * Libgcrypt is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

/*
  This module switches between different implementations of random
  number generators and provides a few help functions.
 */

#include <config.h>

#include <neopg/crypto/rng.h>

#include "g10lib.h"

/* ---  Functions  --- */

/* Add BUFLEN bytes from BUF to the internal random pool.  */
gpg_error_t _gcry_random_add_bytes(const void *buf, size_t buflen) {
  NeoPG::rng()->add_entropy((Botan::byte *)buf, buflen);
  return 0;
}

static void do_randomize(void *buffer, size_t length) {
  NeoPG::rng()->randomize((Botan::byte *)buffer, length);
}

/* The public function to return random data.
   Returns a pointer to a newly allocated and randomized buffer of NBYTES
   length.  Caller must free the buffer.  */
void *_gcry_random_bytes(size_t nbytes) {
  void *buffer = xmalloc(nbytes);
  do_randomize(buffer, nbytes);
  return buffer;
}

/* The public function to return random data.
   this version of the function returns the random in a buffer allocated
   in secure memory.  Caller must free the buffer. */
void *_gcry_random_bytes_secure(size_t nbytes) {
  void *buffer = xmalloc_secure(nbytes);
  do_randomize(buffer, nbytes);
  return buffer;
}

/* Public function to fill the buffer with LENGTH bytes of
   cryptographically strong random bytes.  */
void _gcry_randomize(void *buffer, size_t length) {
  do_randomize(buffer, length);
}

/* Create an unpredicable nonce of LENGTH bytes in BUFFER. */
void _gcry_create_nonce(void *buffer, size_t length) {
  do_randomize(buffer, length);
}
