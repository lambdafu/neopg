// OpenPGP DSA public key material (tests)
// Copyright 2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/openpgp/public_key/material/dsa_public_key_material.h>

#include <gtest/gtest.h>

#include <memory>
#include <sstream>

using namespace NeoPG;

TEST(OpenpgpDsaPublicKeyMaterial, Create) {
  const auto raw =
      std::string{"\x00\x09\x01\x62\x00\x02\x03\x00\x02\x02\x00\x01\x01", 13};

  ParserInput in(raw.data(), raw.length());
  auto dsa_ptr = DsaPublicKeyMaterial::create_or_throw(in);
  ASSERT_EQ(in.size(), 0);

  DsaPublicKeyMaterial& dsa{*dsa_ptr};
  ASSERT_EQ(dsa.algorithm(), PublicKeyAlgorithm::Dsa);
  ASSERT_EQ(dsa.m_p, MultiprecisionInteger(0x162));
  ASSERT_EQ(dsa.m_q, MultiprecisionInteger(3));
  ASSERT_EQ(dsa.m_g, MultiprecisionInteger(2));
  ASSERT_EQ(dsa.m_y, MultiprecisionInteger(1));

  std::stringstream out;
  dsa.write(out);
  ASSERT_EQ(out.str(), raw);
}
