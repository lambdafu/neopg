// OpenPGP signature expiration time subpacket (tests)
// Copyright 2017-2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/openpgp/signature/subpacket/signature_expiration_time_subpacket.h>

#include "gtest/gtest.h"

#include <memory>
#include <sstream>

using namespace NeoPG;

TEST(OpenpgpSignatureExpirationTimeSubpacket, Create) {
  {
    std::stringstream out;
    SignatureExpirationTimeSubpacket packet;
    packet.m_expiration = 0x12345678;
    packet.write(out);
    ASSERT_EQ(out.str(), std::string("\x05\x03\x12\x34\x56\x78", 6));
  }
}

TEST(OpenpgpSignatureExpirationTimeSubpacket, ParseShort) {
  // Test parser (packet too short)
  const auto packet = std::vector<uint8_t>(3, 0xff);
  ParserInput in{(const char*)packet.data(), packet.size()};

  ASSERT_ANY_THROW(SignatureExpirationTimeSubpacket::create_or_throw(in));
  ASSERT_EQ(in.position(), 0);
}

TEST(OpenpgpSignatureExpirationTimeSubpacket, ParseLong) {
  // Test parser (packet too long)
  const auto packet = std::vector<uint8_t>(5, 0xff);
  ParserInput in{(const char*)packet.data(), packet.size()};

  ASSERT_ANY_THROW(SignatureExpirationTimeSubpacket::create_or_throw(in));
  ASSERT_EQ(in.position(), 4);
}
