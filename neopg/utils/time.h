/* Time functions
   Copyright 2017 The NeoPG developers

   NeoPG is released under the Simplified BSD License (see license.txt)
*/

#pragma once

#include <neopg/utils/common.h>
#include <time.h>

namespace NeoPG {

/**
   A replacement for timegm.
*/
time_t NEOPG_UNSTABLE_API timegm(struct tm *tm);

}  // namespace NeoPG
