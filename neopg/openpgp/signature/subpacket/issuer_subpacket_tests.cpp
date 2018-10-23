// OpenPGP issuer subpacket (tests)
// Copyright 2017-2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/openpgp/signature/subpacket/issuer_subpacket.h>

#include "gtest/gtest.h"

#include <memory>
#include <sstream>

using namespace NeoPG;

TEST(OpenpgpIssuerSubpacket, Create) {
  {
    std::stringstream out;
    IssuerSubpacket packet;
    packet.m_issuer =
        std::vector<uint8_t>{{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}};
    packet.write(out);
    ASSERT_EQ(out.str(),
              std::string("\x09\x10\x01\x02\x03\x04\x05\x06\x07\x08", 10));
  }
}

TEST(OpenpgpIssuerSubpacket, ParseBad) {
  // Test parser (packet too long)
  const auto packet = std::vector<uint8_t>(9, 0xff);
  ParserInput in{(const char*)packet.data(), packet.size()};

  ASSERT_ANY_THROW(IssuerSubpacket::create_or_throw(in));
  ASSERT_EQ(in.position(), (uint32_t)8);
}
