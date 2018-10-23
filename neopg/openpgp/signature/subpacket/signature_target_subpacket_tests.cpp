// OpenPGP signature target subpacket (tests)
// Copyright 2017-2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/openpgp/signature/subpacket/signature_target_subpacket.h>

#include "gtest/gtest.h"

#include <memory>
#include <sstream>

using namespace NeoPG;

TEST(OpenpgpSignatureTargetSubpacket, Create) {
  {
    std::stringstream out;
    SignatureTargetSubpacket packet;
    packet.m_public_key_algorithm = PublicKeyAlgorithm::Rsa;
    packet.m_hash_algorithm = HashAlgorithm::Sha1;
    packet.m_hash = std::vector<uint8_t>(20, 0x30);
    packet.write(out);
    ASSERT_EQ(out.str(), std::string("\x17\x1f\x01\x02"
                                     "00000000000000000000",
                                     24));
  }
}

TEST(OpenpgpSignatureTargetSubpacket, ParseShort) {
  // Test parser (packet too long)
  ParserInput in{""};

  ASSERT_ANY_THROW(SignatureTargetSubpacket::create_or_throw(in));
  ASSERT_EQ(in.position(), 0);
}

TEST(OpenpgpSignatureTargetSubpacket, ParseLong) {
  // Test parser (packet too long). Needs to be known hash (SHA-1 here).
  const auto packet = std::vector<uint8_t>(23, 0x02);
  ParserInput in{(const char*)packet.data(), packet.size()};

  ASSERT_ANY_THROW(SignatureTargetSubpacket::create_or_throw(in));
  // Because we test hash size after parsing, we get a late error.
  ASSERT_EQ(in.position(), 23);
}
