// OpenPGP key expiration time subpacket (tests)
// Copyright 2017-2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/openpgp/signature/subpacket/key_expiration_time_subpacket.h>

#include "gtest/gtest.h"

#include <memory>
#include <sstream>

using namespace NeoPG;

TEST(OpenpgpKeyExpirationTimeSubpacket, Create) {
  {
    std::stringstream out;
    KeyExpirationTimeSubpacket packet;
    packet.m_expiration = 0x12345678;
    packet.write(out);
    ASSERT_EQ(out.str(), std::string("\x05\x09\x12\x34\x56\x78", 6));
  }
}

TEST(OpenpgpKeyExpirationTimeSubpacket, ParseShort) {
  // Test parser (packet too short)
  const auto uid = std::vector<uint8_t>(3, 0xff);
  ParserInput in{(const char*)uid.data(), uid.size()};

  ASSERT_ANY_THROW(KeyExpirationTimeSubpacket::create_or_throw(in));
  ASSERT_EQ(in.position(), 0);
}
