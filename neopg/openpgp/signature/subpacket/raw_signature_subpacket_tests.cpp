// OpenPGP raw signature subpacket (tests)
// Copyright 2017-2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/openpgp/signature/subpacket/raw_signature_subpacket.h>

#include "gtest/gtest.h"

#include <memory>
#include <sstream>

using namespace NeoPG;

TEST(OpenpgpRawSignatureSubpacket, Create) {
  {
    std::stringstream out;
    RawSignatureSubpacket packet;
    packet.m_type = SignatureSubpacketType::SignatureCreationTime;
    packet.m_content = std::string("\x12\x34\x56\x78", 4);
    packet.write(out);
    ASSERT_EQ(out.str(), std::string("\x05\x02\x12\x34\x56\x78", 6));
  }
}

TEST(OpenpgpRawSignatureSubpacket, ParseBad) {
  // Test parser (packet too long)
  const auto uid =
      std::vector<uint8_t>(RawSignatureSubpacket::MAX_LENGTH + 1, 0xff);
  ParserInput in{(const char*)uid.data(), uid.size()};

  ASSERT_ANY_THROW(RawSignatureSubpacket::create_or_throw(
      SignatureSubpacketType::SignatureCreationTime, in));
  ASSERT_EQ(in.position(), (uint32_t)RawSignatureSubpacket::MAX_LENGTH);
}
