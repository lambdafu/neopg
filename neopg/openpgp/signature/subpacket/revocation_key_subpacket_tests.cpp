// OpenPGP revocation key subpacket (tests)
// Copyright 2017-2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/openpgp/signature/subpacket/revocation_key_subpacket.h>

#include "gtest/gtest.h"

#include <memory>
#include <sstream>

using namespace NeoPG;

TEST(OpenpgpRevocationKeySubpacket, Create) {
  {
    std::stringstream out;
    RevocationKeySubpacket packet;
    packet.m_class = 0x80;
    packet.m_algorithm = PublicKeyAlgorithm::Rsa;
    packet.m_fingerprint = std::vector<uint8_t>(20, 0x30);
    packet.write(out);
    ASSERT_EQ(out.str(), std::string("\x17\x0c\x80\x01"
                                     "00000000000000000000",
                                     24));
  }
}

TEST(OpenpgpRevocationKeySubpacket, ParseShort) {
  // Test parser (packet too long)
  ParserInput in{""};

  ASSERT_ANY_THROW(RevocationKeySubpacket::create_or_throw(in));
  ASSERT_EQ(in.position(), 0);
}

TEST(OpenpgpRevocationKeySubpacket, ParseLong) {
  // Test parser (packet too long)
  const auto packet = std::vector<uint8_t>(23, 0xff);
  ParserInput in{(const char*)packet.data(), packet.size()};

  ASSERT_ANY_THROW(RevocationKeySubpacket::create_or_throw(in));
  ASSERT_EQ(in.position(), 22);
}
