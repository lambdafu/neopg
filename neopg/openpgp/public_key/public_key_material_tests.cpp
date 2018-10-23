// OpenPGP public key material (tests)
// Copyright 2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/openpgp/public_key/public_key_material.h>

#include <neopg/openpgp/public_key/material/rsa_public_key_material.h>

#include <gtest/gtest.h>

#include <memory>
#include <sstream>

using namespace NeoPG;

TEST(OpenpgpPublicKeyMaterial, CreateRsa) {
  const auto raw = std::string{"\x00\x09\x01\x62\x00\x02\x03", 7};

  ParserInput in(raw.data(), raw.length());
  auto mat = PublicKeyMaterial::create_or_throw(PublicKeyAlgorithm::Rsa, in);
  ASSERT_EQ(in.size(), 0);

  auto rsa_ptr = dynamic_cast<RsaPublicKeyMaterial*>(mat.get());
  ASSERT_NE(rsa_ptr, nullptr);

  RsaPublicKeyMaterial& rsa{*rsa_ptr};
  ASSERT_EQ(rsa.algorithm(), PublicKeyAlgorithm::Rsa);
  ASSERT_EQ(rsa.m_n, MultiprecisionInteger(0x162));
  ASSERT_EQ(rsa.m_e, MultiprecisionInteger(3));

  std::stringstream out;
  rsa.write(out);
  ASSERT_EQ(out.str(), raw);
}
