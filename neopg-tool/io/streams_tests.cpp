/* Tests for openpgp parser
   Copyright 2017 The NeoPG developers

   NeoPG is released under the Simplified BSD License (see license.txt)
*/

#include "gtest/gtest.h"

#include <neopg-tool/io/streams.h>

using namespace NeoPG;

namespace NeoPG {

TEST(NeopgToolTest, streams_test) {
  {
    streams.m_data.in();
    ASSERT_THROW(streams.m_console.in(), std::runtime_error);
  }
}
}  // namespace NeoPG
