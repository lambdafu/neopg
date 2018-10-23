// OpenPGP signature data (tests)
// Copyright 2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/openpgp/signature/data/v3_signature_data.h>

#include <neopg/openpgp/signature/material/rsa_signature_material.h>

#include <gtest/gtest.h>

#include <memory>
#include <sstream>

using namespace NeoPG;

TEST(OpenpgpV3SignatureData, Create) {
  // Test V3 packets.
  const std::string raw{
      "\x05\x10\x12\x34\x56\x78"
      "\xab\xcd\xef\xab\xcd\xef\xab\xcd"
      "\x01"
      "\x02"
      "\x67\x89"
      "\x00\x11\x01\x42\x23",
      23};
  ParserInput in(raw.data(), raw.length());
  auto signature = V3SignatureData::create_or_throw(in);
  ASSERT_EQ(signature->version(), SignatureVersion::V3);
  auto v3sig = dynamic_cast<V3SignatureData*>(signature.get());
  ASSERT_NE(v3sig, nullptr);
  ASSERT_EQ(v3sig->m_type, static_cast<SignatureType>(0x10));
  ASSERT_EQ(v3sig->m_created, 0x12345678);

  std::array<uint8_t, 8> signer{
      {0xab, 0xcd, 0xef, 0xab, 0xcd, 0xef, 0xab, 0xcd}};
  ASSERT_EQ(v3sig->m_signer, signer);

  std::array<uint8_t, 2> quick{{0x67, 0x89}};
  ASSERT_EQ(v3sig->m_quick, quick);

  ASSERT_EQ(v3sig->m_public_key_algorithm, PublicKeyAlgorithm::Rsa);
  ASSERT_EQ(v3sig->m_hash_algorithm, HashAlgorithm::Sha1);
  ASSERT_NE(v3sig->m_signature, nullptr);
  ASSERT_EQ(v3sig->m_signature->algorithm(), PublicKeyAlgorithm::Rsa);
  auto rsa = dynamic_cast<RsaSignatureMaterial*>(v3sig->m_signature.get());
  ASSERT_EQ(rsa->m_m_pow_d, MultiprecisionInteger(0x14223));
}
