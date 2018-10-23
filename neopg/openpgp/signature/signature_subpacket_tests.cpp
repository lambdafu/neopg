// OpenPGP signature subpacket (tests)
// Copyright 2017-2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/openpgp/signature/signature_subpacket.h>

#include <neopg/openpgp/signature/subpacket/raw_signature_subpacket.h>

#include "gtest/gtest.h"

#include <memory>
#include <sstream>

using namespace NeoPG;

TEST(OpenpgpSignatureSubpacket, CreateDefaultLengthType) {
  std::stringstream out;
  RawSignatureSubpacket sub;

  sub.write(out);
  ASSERT_EQ(out.str(), std::string("\x01\x00", 2));
}

TEST(OpenpgpSignatureSubpacket, CreateOneOctetLength) {
  std::stringstream out;
  RawSignatureSubpacket sub;

  sub.write(out, SignatureSubpacketLengthType::OneOctet);
  ASSERT_EQ(out.str(), std::string("\x01\x00", 2));
}

TEST(OpenpgpSignatureSubpacket, CreateFiveOctetLength) {
  std::stringstream out;
  RawSignatureSubpacket sub;

  sub.write(out, SignatureSubpacketLengthType::FiveOctet);
  ASSERT_EQ(out.str(), std::string("\xff\x00\x00\x00\x01\x00", 6));
}
