// OpenPGP signature data (tests)
// Copyright 2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/openpgp/signature/data/v4_signature_subpacket_data.h>

#include <gtest/gtest.h>

#include <memory>
#include <sstream>

using namespace NeoPG;

TEST(OpenpgpV4SignatureSubpacketData, CreateEmpty) {
  const std::string raw{"\x00\x00", 2};
  ParserInput in(raw.data(), raw.length());
  auto data = V4SignatureSubpacketData::create_or_throw(in);
  ASSERT_EQ(in.size(), 0);
  ASSERT_EQ(data->m_subpackets.size(), 0);
}

TEST(OpenpgpV4SignatureSubpacketData, CreateOne) {
  const std::string raw{"\x00\x05\x04\x00\x01\x02\x03", 7};
  ParserInput in(raw.data(), raw.length());
  auto data = V4SignatureSubpacketData::create_or_throw(in);
  ASSERT_EQ(in.size(), 0);
  ASSERT_EQ(data->m_subpackets.size(), 1);
}

TEST(OpenpgpV4SignatureSubpacketData, CreateTwo) {
  const std::string raw{"\x00\x0a\x04\x00\x01\x02\x03\x04\x00\x01\x02\x03", 12};
  ParserInput in(raw.data(), raw.length());
  auto data = V4SignatureSubpacketData::create_or_throw(in);
  ASSERT_EQ(in.size(), 0);
  ASSERT_EQ(data->m_subpackets.size(), 2);
}

TEST(OpenpgpV4SignatureSubpacketData, FailZeroLength) {
  const std::string raw{"\x00\x01\x00", 3};
  ParserInput in(raw.data(), raw.length());
  ASSERT_ANY_THROW(V4SignatureSubpacketData::create_or_throw(in));
}

TEST(OpenpgpV4SignatureSubpacketData, FailMissingData) {
  const std::string raw{"\x00\x02\x00", 3};
  ParserInput in(raw.data(), raw.length());
  ASSERT_ANY_THROW(V4SignatureSubpacketData::create_or_throw(in));
}
