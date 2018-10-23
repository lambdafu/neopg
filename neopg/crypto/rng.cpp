/* Random numbers
   Copyright 2017 The NeoPG developers

   NeoPG is released under the Simplified BSD License (see license.txt)
*/

#include <botan/auto_rng.h>
#include <neopg/crypto/rng.h>

namespace NeoPG {

Botan::RandomNumberGenerator* rng(void) {
  static thread_local Botan::RandomNumberGenerator* rng_local;

  /* We delay allocation so that only threads which actually use neopg
     crypto are creating a random pool.  */
  if (rng_local == nullptr) rng_local = new Botan::AutoSeeded_RNG;
  return rng_local;
}

}  // Namespace NeoPG
