// OpenPGP notation_data subpacket (tests)
// Copyright 2017-2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/openpgp/signature/subpacket/notation_data_subpacket.h>

#include "gtest/gtest.h"

#include <memory>
#include <sstream>

using namespace NeoPG;

TEST(OpenpgpNotationDataSubpacket, Create) {
  {
    std::stringstream out;
    NotationDataSubpacket packet;
    packet.m_flags = std::vector<uint8_t>{{0x01, 0x02, 0x03, 0x04}};
    packet.m_name = std::vector<uint8_t>{{0xa1, 0xa2, 0xa3}};
    packet.m_value = std::vector<uint8_t>{{0xb1}};
    packet.write(out);
    ASSERT_EQ(
        out.str(),
        std::string("\x0d\x14\x01\x02\x03\x04\x00\x03\x00\x01\xa1\xa2\xa3\xb1",
                    14));
  }
}

TEST(OpenpgpNotationDataSubpacket, ParseBad) {
  // Test parser (packet too short)
  const auto packet = std::vector<uint8_t>(5, 0xff);
  ParserInput in{(const char*)packet.data(), packet.size()};

  ASSERT_ANY_THROW(NotationDataSubpacket::create_or_throw(in));
  ASSERT_EQ(in.position(), (uint32_t)4);
}
