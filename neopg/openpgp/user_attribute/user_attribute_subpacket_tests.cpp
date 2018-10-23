// OpenPGP user_attribute subpacket (tests)
// Copyright 2017-2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/openpgp/user_attribute/user_attribute_subpacket.h>

#include <neopg/openpgp/user_attribute/subpacket/raw_user_attribute_subpacket.h>

#include "gtest/gtest.h"

#include <memory>
#include <sstream>

using namespace NeoPG;

TEST(OpenpgpUserAttributeSubpacket, CreateDefaultLengthType) {
  std::stringstream out;
  RawUserAttributeSubpacket sub;

  sub.write(out);
  ASSERT_EQ(out.str(), std::string("\x01\x00", 2));
}

TEST(OpenpgpUserAttributeSubpacket, CreateOneOctetLength) {
  std::stringstream out;
  RawUserAttributeSubpacket sub;

  sub.write(out, UserAttributeSubpacketLengthType::OneOctet);
  ASSERT_EQ(out.str(), std::string("\x01\x00", 2));
}

TEST(OpenpgpUserAttributeSubpacket, CreateFiveOctetLength) {
  std::stringstream out;
  RawUserAttributeSubpacket sub;

  sub.write(out, UserAttributeSubpacketLengthType::FiveOctet);
  ASSERT_EQ(out.str(), std::string("\xff\x00\x00\x00\x01\x00", 6));
}
