// OpenPGP public key packet (tests)
// Copyright 2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/openpgp/public_key_packet.h>

#include <gtest/gtest.h>

#include <memory>
#include <sstream>

using namespace NeoPG;

TEST(OpenpgpPublicKeyPacket, WriteWithOldHeader) {
  // Test old packet header.
  std::stringstream out;
  PublicKeyPacket packet;

  packet.write(out, OldPacketHeader::create_or_throw);
  // Not really a packet, but good enough for testing.
  ASSERT_EQ(out.str(), std::string("\x98\x01\x04", 3));
}

TEST(OpenpgpPublicKeyPacket, WriteWithNewHeader) {
  // Test new packet header.
  std::stringstream out;
  PublicKeyPacket packet;
  packet.write(out);
  ASSERT_EQ(out.str(), std::string("\xc6\x01\x04", 3));
}

TEST(OpenpgpPublicKeyPacket, ParseV3) {
  // Test V3 packets.
  const std::string raw{
      "\x03"
      "\x12\x34\x56\x78"
      "\xab\xcd"
      "\x01"
      "\x00\x11\x01\x42\x23"
      "\x00\x02\x03",
      16};
  ParserInput in(raw.data(), raw.length());
  auto packet = PublicKeyPacket::create_or_throw(in);
  ASSERT_EQ(packet->version(), PublicKeyVersion::V3);
  auto public_key = packet->m_public_key.get();
  ASSERT_NE(public_key, nullptr);
  ASSERT_EQ(public_key->version(), PublicKeyVersion::V3);

  // Test writing.
  std::stringstream out;
  packet->write_body(out);
  ASSERT_EQ(out.str(), raw);
}

TEST(OpenpgpPublicKeyPacket, ParseV4) {
  // Test V4 packets.
  const std::string raw{
      "\x04"
      "\x12\x34\x56\x78"
      "\x01"
      "\x00\x11\x01\x42\x23"
      "\x00\x02\x03",
      14};
  ParserInput in(raw.data(), raw.length());
  auto packet = PublicKeyPacket::create_or_throw(in);
  ASSERT_EQ(packet->version(), PublicKeyVersion::V4);
  auto public_key = packet->m_public_key.get();
  ASSERT_NE(public_key, nullptr);
  ASSERT_EQ(public_key->version(), PublicKeyVersion::V4);

  // Test writing.
  std::stringstream out;
  packet->write_body(out);
  ASSERT_EQ(out.str(), raw);
}
