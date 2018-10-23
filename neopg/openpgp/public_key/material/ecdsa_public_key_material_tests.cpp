// OpenPGP ECDSA public key material (tests)
// Copyright 2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/openpgp/public_key/material/ecdsa_public_key_material.h>

#include <gtest/gtest.h>

#include <memory>
#include <sstream>

using namespace NeoPG;

TEST(OpenpgpEcdsaPublicKeyMaterial, Create) {
  const auto raw = std::string{"\x05\x2b\x81\x04\x00\x23\x00\x02\x03", 9};

  ParserInput in(raw.data(), raw.length());
  auto ecdsa_ptr = EcdsaPublicKeyMaterial::create_or_throw(in);
  ASSERT_EQ(in.size(), 0);

  EcdsaPublicKeyMaterial& ecdsa{*ecdsa_ptr};
  ASSERT_EQ(ecdsa.algorithm(), PublicKeyAlgorithm::Ecdsa);
  ASSERT_EQ(ecdsa.m_curve.as_string(), "1.3.132.0.35");
  ASSERT_EQ(ecdsa.m_key, MultiprecisionInteger(0x3));

  std::stringstream out;
  ecdsa.write(out);
  ASSERT_EQ(out.str(), raw);
}
