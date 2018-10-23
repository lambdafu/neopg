// OpenPGP user attribute packet (tests)
// Copyright 2017-2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/openpgp/user_attribute_packet.h>

#include <gtest/gtest.h>

#include <memory>
#include <sstream>

using namespace NeoPG;

TEST(OpenpgpUserAttributePacket, NewHeader) {
  UserAttributePacket packet;
  std::stringstream out;

  packet.write(out);
  ASSERT_EQ(out.str(), std::string("\xd1\x00", 2));
}
