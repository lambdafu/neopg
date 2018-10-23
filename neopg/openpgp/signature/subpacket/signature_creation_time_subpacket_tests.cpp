// OpenPGP signature creation time subpacket (tests)
// Copyright 2017-2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/openpgp/signature/subpacket/signature_creation_time_subpacket.h>

#include "gtest/gtest.h"

#include <memory>
#include <sstream>

using namespace NeoPG;

TEST(OpenpgpSignatureCreationTimeSubpacket, Create) {
  {
    std::stringstream out;
    SignatureCreationTimeSubpacket packet;
    packet.m_created = 0x12345678;
    packet.write(out);
    ASSERT_EQ(out.str(), std::string("\x05\x02\x12\x34\x56\x78", 6));
  }
}

TEST(OpenpgpSignatureCreationTimeSubpacket, ParseShort) {
  // Test parser (packet too short)
  const auto packet = std::vector<uint8_t>(3, 0xff);
  ParserInput in{(const char*)packet.data(), packet.size()};

  ASSERT_ANY_THROW(SignatureCreationTimeSubpacket::create_or_throw(in));
  ASSERT_EQ(in.position(), 0);
}
