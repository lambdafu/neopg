// OpenPGP signers user id subpacket (tests)
// Copyright 2017-2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/openpgp/signature/subpacket/signers_user_id_subpacket.h>

#include "gtest/gtest.h"

#include <memory>
#include <sstream>

using namespace NeoPG;

TEST(OpenpgpSignersUserIdSubpacket, Create) {
  {
    std::stringstream out;
    SignersUserIdSubpacket packet;
    packet.m_user_id = std::string("\x12\x34\x56\x78", 4);
    packet.write(out);
    ASSERT_EQ(out.str(), std::string("\x05\x1c\x12\x34\x56\x78", 6));
  }
}

TEST(OpenpgpSignersUserIdSubpacket, ParseBad) {
  // Test parser (packet too long)
  const auto packet =
      std::vector<uint8_t>(SignersUserIdSubpacket::MAX_LENGTH + 1, 0xff);
  ParserInput in{(const char*)packet.data(), packet.size()};

  ASSERT_ANY_THROW(SignersUserIdSubpacket::create_or_throw(in));
  ASSERT_EQ(in.position(), (uint32_t)SignersUserIdSubpacket::MAX_LENGTH);
}
