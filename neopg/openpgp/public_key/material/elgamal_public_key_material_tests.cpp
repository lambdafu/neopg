// OpenPGP Elgamal public key material (tests)
// Copyright 2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/openpgp/public_key/material/elgamal_public_key_material.h>

#include <gtest/gtest.h>

#include <memory>
#include <sstream>

using namespace NeoPG;

TEST(OpenpgpElgamalPublicKeyMaterial, Create) {
  const auto raw = std::string{"\x00\x09\x01\x62\x00\x02\x03\x00\x02\x02", 10};

  ParserInput in(raw.data(), raw.length());
  auto elgamal_ptr = ElgamalPublicKeyMaterial::create_or_throw(in);
  ASSERT_EQ(in.size(), 0);

  ElgamalPublicKeyMaterial& elgamal{*elgamal_ptr};
  ASSERT_EQ(elgamal.algorithm(), PublicKeyAlgorithm::Elgamal);
  ASSERT_EQ(elgamal.m_p, MultiprecisionInteger(0x162));
  ASSERT_EQ(elgamal.m_g, MultiprecisionInteger(3));
  ASSERT_EQ(elgamal.m_y, MultiprecisionInteger(2));

  std::stringstream out;
  elgamal.write(out);
  ASSERT_EQ(out.str(), raw);
}
