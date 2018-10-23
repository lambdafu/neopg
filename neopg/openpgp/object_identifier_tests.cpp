// OpenPGP object identifier (tests)
// Copyright 2017-2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/openpgp/object_identifier.h>

#include <gtest/gtest.h>

#include <memory>
#include <sstream>

using namespace NeoPG;

TEST(NeopgTest, openpgp_object_identifier_test) {
  {
    std::stringstream out;
    ObjectIdentifier oid;
    oid.m_data.assign({0x2b, 0x81, 0x04, 0x00, 0x23});
    oid.write(out);
    ASSERT_EQ(out.str(), std::string("\x05\x2b\x81\x04\x00\x23", 6));
    ASSERT_EQ(oid.as_string(), std::string("1.3.132.0.35"));
  }
}
