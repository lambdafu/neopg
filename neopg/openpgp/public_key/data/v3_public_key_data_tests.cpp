// OpenPGP v3 public key packet data (tests)
// Copyright 2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/openpgp/public_key/data/v3_public_key_data.h>

#include <neopg/openpgp/public_key/material/rsa_public_key_material.h>

#include <neopg/intern/cplusplus.h>

#include <gtest/gtest.h>

#include <memory>
#include <sstream>

using namespace NeoPG;

TEST(OpenpgpV3PublicKeyData, Create) {
  // Test V3 packets.
  const std::string raw{
      "\x12\x34\x56\x78"
      "\xab\xcd"
      "\x01"
      "\x00\x11\x01\x42\x23"
      "\x00\x02\x03",
      15};
  auto fpr =
      std::vector<uint8_t>{0xb5, 0xb5, 0xbe, 0xc2, 0x3d, 0x70, 0xea, 0x0e,
                           0x05, 0x68, 0x45, 0x64, 0xac, 0xa7, 0x3d, 0xc7};
  auto keyid =
      std::vector<uint8_t>{0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x42, 0x23};
  ParserInput in(raw.data(), raw.length());
  auto key = PublicKeyData::create_or_throw(PublicKeyVersion::V3, in);
  ASSERT_EQ(key->version(), PublicKeyVersion::V3);
  auto v3key = dynamic_cast<V3PublicKeyData*>(key.get());
  ASSERT_NE(v3key, nullptr);
  ASSERT_EQ(v3key->m_created, 0x12345678);
  ASSERT_EQ(v3key->m_days_valid, 0xabcd);
  ASSERT_EQ(v3key->m_algorithm, PublicKeyAlgorithm::Rsa);
  ASSERT_NE(v3key->m_key, nullptr);
  ASSERT_EQ(v3key->m_key->algorithm(), PublicKeyAlgorithm::Rsa);
  ASSERT_EQ(v3key->fingerprint(), fpr);
  ASSERT_EQ(v3key->keyid(), keyid);
  auto rsa = dynamic_cast<RsaPublicKeyMaterial*>(v3key->m_key.get());
  ASSERT_EQ(rsa->m_n, MultiprecisionInteger(0x14223));
  ASSERT_EQ(rsa->m_e, MultiprecisionInteger(0x3));

  std::stringstream out;
  v3key->write(out);
  ASSERT_EQ(out.str(), raw);
}

TEST(OpenpgpV3PublicKeyData, KeyId) {
  V3PublicKeyData v3key;
  v3key.m_key = make_unique<RsaPublicKeyMaterial>();
  auto rsa = dynamic_cast<RsaPublicKeyMaterial*>(v3key.m_key.get());
  rsa->m_n.m_bits = std::vector<uint8_t>{0xff, 0x08, 0x07, 0x06, 0x05,
                                         0x04, 0x03, 0x02, 0x01, 0x00};
  rsa->m_n.m_length = rsa->m_n.m_bits.size() * 8;
  auto keyid =
      std::vector<uint8_t>{0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00};
  ASSERT_EQ(v3key.keyid(), keyid);
}

TEST(OpenpgpV3PublicKeyData, ShortKeyId) {
  V3PublicKeyData v3key;
  v3key.m_key = make_unique<RsaPublicKeyMaterial>();
  auto rsa = dynamic_cast<RsaPublicKeyMaterial*>(v3key.m_key.get());
  rsa->m_n.m_bits = std::vector<uint8_t>{0xff, 0x01, 0x00};
  rsa->m_n.m_length = rsa->m_n.m_bits.size() * 8;
  auto keyid =
      std::vector<uint8_t>{0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x01, 0x00};
  ASSERT_EQ(v3key.keyid(), keyid);
}
