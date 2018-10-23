// OpenPGP RSA public key material (tests)
// Copyright 2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/openpgp/public_key/material/rsa_public_key_material.h>

#include <gtest/gtest.h>

#include <memory>
#include <sstream>

using namespace NeoPG;

TEST(OpenpgpRsaPublicKeyMaterial, Create) {
  const auto raw = std::string{"\x00\x09\x01\x62\x00\x02\x03", 7};

  ParserInput in(raw.data(), raw.length());
  auto rsa_ptr = RsaPublicKeyMaterial::create_or_throw(in);
  ASSERT_EQ(in.size(), 0);

  RsaPublicKeyMaterial& rsa{*rsa_ptr};
  ASSERT_EQ(rsa.algorithm(), PublicKeyAlgorithm::Rsa);
  ASSERT_EQ(rsa.m_n, MultiprecisionInteger(0x162));
  ASSERT_EQ(rsa.m_e, MultiprecisionInteger(3));

  std::stringstream out;
  rsa.write(out);
  ASSERT_EQ(out.str(), raw);
}

TEST(OpenpgpRsaPublicKeyMaterial, ParseError) {
  const auto raw = std::string{"\x00\x09\x01\x62\x00\x02\x03\x00\x02\x02", 10};
  ParserInput in1(raw.data(), raw.length());
  ASSERT_NO_THROW(RsaPublicKeyMaterial::create_or_throw(in1));
  ASSERT_EQ(in1.position(), 7);

  ParserInput in2(raw.data(), raw.length() - 6);
  ASSERT_ANY_THROW(RsaPublicKeyMaterial::create_or_throw(in2));

  ParserInput in3(raw.data(), raw.length() - 3);
  in3.bump(4);
  ASSERT_ANY_THROW(RsaPublicKeyMaterial::create_or_throw(in3));
}
