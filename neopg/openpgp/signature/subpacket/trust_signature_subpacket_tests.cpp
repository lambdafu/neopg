// OpenPGP trust signature subpacket (tests)
// Copyright 2017-2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/openpgp/signature/subpacket/trust_signature_subpacket.h>

#include "gtest/gtest.h"

#include <memory>
#include <sstream>

using namespace NeoPG;

TEST(OpenpgpTrustSignatureSubpacket, Create) {
  {
    std::stringstream out;
    TrustSignatureSubpacket packet;
    packet.m_level = 0xab;
    packet.m_amount = 0xcd;
    packet.write(out);
    ASSERT_EQ(out.str(), std::string("\x03\x05\xab\xcd", 4));
  }
}

TEST(OpenpgpTrustSignatureSubpacket, ParseShort) {
  // Test parser (packet too long)
  ParserInput in{""};

  ASSERT_ANY_THROW(TrustSignatureSubpacket::create_or_throw(in));
  ASSERT_EQ(in.position(), 0);
}

TEST(OpenpgpTrustSignatureSubpacket, ParseLong) {
  // Test parser (packet too long)
  const auto packet = std::vector<uint8_t>(3, 0xff);
  ParserInput in{(const char*)packet.data(), packet.size()};

  ASSERT_ANY_THROW(TrustSignatureSubpacket::create_or_throw(in));
  ASSERT_EQ(in.position(), 2);
}
