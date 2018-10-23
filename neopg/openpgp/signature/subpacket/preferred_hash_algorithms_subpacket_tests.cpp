// OpenPGP preferred hash algorithms subpacket (tests)
// Copyright 2017-2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/openpgp/signature/subpacket/preferred_hash_algorithms_subpacket.h>

#include "gtest/gtest.h"

#include <memory>
#include <sstream>

using namespace NeoPG;

TEST(OpenpgpPreferredHashAlgorithmsSubpacket, Create) {
  {
    std::stringstream out;
    PreferredHashAlgorithmsSubpacket packet;
    packet.m_algorithms = std::vector<uint8_t>{{0x12, 0x34, 0x56, 0x78}};
    packet.write(out);
    ASSERT_EQ(out.str(), std::string("\x05\x15\x12\x34\x56\x78", 6));
  }
}

TEST(OpenpgpPreferredHashAlgorithmsSubpacket, ParseBad) {
  // Test parser (packet too long)
  const auto packet = std::vector<uint8_t>(
      PreferredHashAlgorithmsSubpacket::MAX_LENGTH + 1, 0xff);
  ParserInput in{(const char*)packet.data(), packet.size()};

  ASSERT_ANY_THROW(PreferredHashAlgorithmsSubpacket::create_or_throw(in));
  ASSERT_EQ(in.position(),
            (uint32_t)PreferredHashAlgorithmsSubpacket::MAX_LENGTH);
}
