/* Random numbers
   Copyright 2017 The NeoPG developers

   NeoPG is released under the Simplified BSD License (see license.txt)
*/

#pragma once

#include <botan/rng.h>

#include <neopg/utils/common.h>

namespace NeoPG {

NEOPG_DLL Botan::RandomNumberGenerator* rng(void);

}  // Namespace NeoPG
