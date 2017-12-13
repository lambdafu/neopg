/* Tests for stream functions
   Copyright 2017 The NeoPG developers

   NeoPG is released under the Simplified BSD License (see license.txt)
*/

#include <neopg/proto/http.h>
#include "gtest/gtest.h"

using namespace NeoPG;

namespace NeoPG {

TEST(NeoPGTest, proto_http_test) {
  {
    Proto::Http request;
    request.set_url("http://www.example.com");

    /* FIXME: This requires network access. */
    // request.fetch();
  }
}
}
