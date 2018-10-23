// OpenPGP EDDSA public key material (tests)
// Copyright 2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/openpgp/public_key/material/eddsa_public_key_material.h>

#include <gtest/gtest.h>

#include <memory>
#include <sstream>

using namespace NeoPG;

TEST(OpenpgpEddsaPublicKeyMaterial, Create) {
  const auto raw = std::string{"\x05\x2b\x81\x04\x00\x23\x00\x02\x03", 9};

  ParserInput in(raw.data(), raw.length());
  auto eddsa_ptr = EddsaPublicKeyMaterial::create_or_throw(in);
  ASSERT_EQ(in.size(), 0);

  EddsaPublicKeyMaterial& eddsa{*eddsa_ptr};
  ASSERT_EQ(eddsa.algorithm(), PublicKeyAlgorithm::Eddsa);
  ASSERT_EQ(eddsa.m_curve.as_string(), "1.3.132.0.35");
  ASSERT_EQ(eddsa.m_key, MultiprecisionInteger(0x03));

  std::stringstream out;
  eddsa.write(out);
  ASSERT_EQ(out.str(), raw);
}
