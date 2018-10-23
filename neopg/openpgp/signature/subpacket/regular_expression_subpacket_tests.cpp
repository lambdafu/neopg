// OpenPGP regular expression subpacket (tests)
// Copyright 2017-2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/openpgp/signature/subpacket/regular_expression_subpacket.h>

#include "gtest/gtest.h"

#include <memory>
#include <sstream>

using namespace NeoPG;

TEST(OpenpgpRegularExpressionSubpacket, Create) {
  {
    std::stringstream out;
    RegularExpressionSubpacket packet;
    packet.m_regex = std::string("\x12\x34\x56\x78", 4);
    packet.write(out);
    ASSERT_EQ(out.str(), std::string("\x05\x06\x12\x34\x56\x78", 6));
  }
}

TEST(OpenpgpRegularExpressionSubpacket, ParseBad) {
  // Test parser (packet too long)
  const auto packet =
      std::vector<uint8_t>(RegularExpressionSubpacket::MAX_LENGTH + 1, 0xff);
  ParserInput in{(const char*)packet.data(), packet.size()};

  ASSERT_ANY_THROW(RegularExpressionSubpacket::create_or_throw(in));
  ASSERT_EQ(in.position(), (uint32_t)RegularExpressionSubpacket::MAX_LENGTH);
}
