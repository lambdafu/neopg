// OpenPGP revocable subpacket (tests)
// Copyright 2017-2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/openpgp/signature/subpacket/revocable_subpacket.h>

#include "gtest/gtest.h"

#include <memory>
#include <sstream>

using namespace NeoPG;

TEST(OpenpgpRevocableSubpacket, Create) {
  {
    std::stringstream out;
    RevocableSubpacket packet;
    packet.m_revocable = 0x01;
    packet.write(out);
    ASSERT_EQ(out.str(), std::string("\x02\x07\x01", 3));
  }
}

TEST(OpenpgpRevocableSubpacket, ParseShort) {
  // Test parser (packet too long)
  ParserInput in{""};

  ASSERT_ANY_THROW(RevocableSubpacket::create_or_throw(in));
  ASSERT_EQ(in.position(), 0);
}

TEST(OpenpgpRevocableSubpacket, ParseLong) {
  // Test parser (packet too long)
  const auto packet = std::vector<uint8_t>(3, 0xff);
  ParserInput in{(const char*)packet.data(), packet.size()};

  ASSERT_ANY_THROW(RevocableSubpacket::create_or_throw(in));
  ASSERT_EQ(in.position(), 1);
}
