// OpenPGP key server preferences subpacket (tests)
// Copyright 2017-2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/openpgp/signature/subpacket/key_server_preferences_subpacket.h>

#include "gtest/gtest.h"

#include <memory>
#include <sstream>

using namespace NeoPG;

TEST(OpenpgpKeyServerPreferencesSubpacket, Create) {
  {
    std::stringstream out;
    KeyServerPreferencesSubpacket packet;
    packet.m_flags = std::vector<uint8_t>{{0x12, 0x34, 0x56, 0x78}};
    packet.write(out);
    ASSERT_EQ(out.str(), std::string("\x05\x17\x12\x34\x56\x78", 6));
  }
}

TEST(OpenpgpKeyServerPreferencesSubpacket, ParseBad) {
  // Test parser (packet too long)
  const auto packet =
      std::vector<uint8_t>(KeyServerPreferencesSubpacket::MAX_LENGTH + 1, 0xff);
  ParserInput in{(const char*)packet.data(), packet.size()};

  ASSERT_ANY_THROW(KeyServerPreferencesSubpacket::create_or_throw(in));
  ASSERT_EQ(in.position(), (uint32_t)KeyServerPreferencesSubpacket::MAX_LENGTH);
}
