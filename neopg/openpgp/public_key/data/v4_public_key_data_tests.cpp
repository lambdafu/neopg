// OpenPGP v4 public key packet data (tests)
// Copyright 2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/openpgp/public_key/data/v4_public_key_data.h>

#include <neopg/openpgp/public_key/material/rsa_public_key_material.h>

#include <neopg/intern/cplusplus.h>

#include <gtest/gtest.h>

#include <memory>
#include <sstream>

using namespace NeoPG;

TEST(OpenpgpV4PublicKeyData, Create) {
  // Test V4 packets.
  const std::string raw{
      "\x12\x34\x56\x78"
      "\x01"
      "\x00\x11\x01\x42\x23"
      "\x00\x02\x03",
      13};
  auto fpr = std::vector<uint8_t>{0x69, 0x33, 0xee, 0xde, 0x37, 0x4c, 0x96,
                                  0xc5, 0x4d, 0xf9, 0x2d, 0x76, 0x5f, 0x46,
                                  0xd7, 0x00, 0xcb, 0x74, 0x27, 0xbf};
  auto keyid = std::vector<uint8_t>{fpr.end() - 8, fpr.end()};
  ParserInput in(raw.data(), raw.length());
  auto key = PublicKeyData::create_or_throw(PublicKeyVersion::V4, in);
  ASSERT_EQ(key->version(), PublicKeyVersion::V4);
  auto v4key = dynamic_cast<V4PublicKeyData*>(key.get());
  ASSERT_NE(v4key, nullptr);
  ASSERT_EQ(v4key->m_created, 0x12345678);
  ASSERT_EQ(v4key->m_algorithm, PublicKeyAlgorithm::Rsa);
  ASSERT_NE(v4key->m_key, nullptr);
  ASSERT_EQ(v4key->m_key->algorithm(), PublicKeyAlgorithm::Rsa);
  ASSERT_EQ(v4key->fingerprint(), fpr);
  ASSERT_EQ(v4key->keyid(), keyid);
  auto rsa = dynamic_cast<RsaPublicKeyMaterial*>(v4key->m_key.get());
  ASSERT_EQ(rsa->m_n, MultiprecisionInteger(0x14223));
  ASSERT_EQ(rsa->m_e, MultiprecisionInteger(0x3));

  std::stringstream out;
  v4key->write(out);
  ASSERT_EQ(out.str(), raw);
}
