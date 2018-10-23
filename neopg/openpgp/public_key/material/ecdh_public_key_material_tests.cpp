// OpenPGP ECDH public key material (tests)
// Copyright 2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/openpgp/public_key/material/ecdh_public_key_material.h>

#include <gtest/gtest.h>

#include <memory>
#include <sstream>

using namespace NeoPG;

TEST(OpenpgpEcdhPublicKeyMaterial, Create) {
  const auto raw =
      std::string{"\x05\x2b\x81\x04\x00\x23\x00\x02\x03\x03\x01\x01\x02", 13};

  ParserInput in(raw.data(), raw.length());
  auto ecdh_ptr = EcdhPublicKeyMaterial::create_or_throw(in);
  ASSERT_EQ(in.size(), 0);

  EcdhPublicKeyMaterial& ecdh{*ecdh_ptr};
  ASSERT_EQ(ecdh.algorithm(), PublicKeyAlgorithm::Ecdh);
  ASSERT_EQ(ecdh.m_curve.as_string(), "1.3.132.0.35");
  ASSERT_EQ(ecdh.m_key, MultiprecisionInteger(0x03));
  ASSERT_EQ(ecdh.m_hash, 0x01);
  ASSERT_EQ(ecdh.m_sym, 0x02);

  std::stringstream out;
  ecdh.write(out);
  ASSERT_EQ(out.str(), raw);
}
