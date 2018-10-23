// OpenPGP policy uri subpacket (tests)
// Copyright 2017-2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/openpgp/signature/subpacket/policy_uri_subpacket.h>

#include "gtest/gtest.h"

#include <memory>
#include <sstream>

using namespace NeoPG;

TEST(OpenpgpPolicyUriSubpacket, Create) {
  {
    std::stringstream out;
    PolicyUriSubpacket packet;
    packet.m_uri = std::string("\x12\x34\x56\x78", 4);
    packet.write(out);
    ASSERT_EQ(out.str(), std::string("\x05\x1a\x12\x34\x56\x78", 6));
  }
}

TEST(OpenpgpPolicyUriSubpacket, ParseBad) {
  // Test parser (packet too long)
  const auto packet =
      std::vector<uint8_t>(PolicyUriSubpacket::MAX_LENGTH + 1, 0xff);
  ParserInput in{(const char*)packet.data(), packet.size()};

  ASSERT_ANY_THROW(PolicyUriSubpacket::create_or_throw(in));
  ASSERT_EQ(in.position(), (uint32_t)PolicyUriSubpacket::MAX_LENGTH);
}
