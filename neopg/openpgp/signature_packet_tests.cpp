// OpenPGP signature packet (tests)
// Copyright 2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/openpgp/signature_packet.h>

#include <gtest/gtest.h>

#include <memory>
#include <sstream>

using namespace NeoPG;

TEST(OpenpgpSignaturePacket, OldHeader) {
  // Test old packet header.
  std::stringstream out;
  SignaturePacket packet;
  packet.m_version = SignatureVersion::V3;
  OldPacketHeader* header = new OldPacketHeader(PacketType::Signature, 1);

  packet.m_header = std::unique_ptr<PacketHeader>(header);
  packet.write(out);
  // Not really a packet, but good enough for testing.
  ASSERT_EQ(out.str(), std::string("\x88\x01\x03", 3));
}

TEST(OpenpgpSignaturePacket, NewHeader) {
  // Test new packet header.
  std::stringstream out;
  SignaturePacket packet;
  packet.write(out);
  ASSERT_EQ(out.str(), std::string("\xc2\x01\x04", 3));
}

TEST(OpenpgpSignaturePacket, CreateV3) {
  // Test V3 signature packets.
  const std::string raw{
      "\x03"
      "\x05\x00\x12\x34\x56\x78"
      "\xab\xcd\xef\xab\xcd\xef\xab\xcd"
      "\x01"
      "\x02"
      "\xde\xad"
      "\x00\x11\x01\x42\x23",
      24};
  ParserInput in(raw.data(), raw.length());
  auto packet = SignaturePacket::create_or_throw(in);
  auto signature = packet->m_signature.get();
  ASSERT_NE(signature, nullptr);
  ASSERT_EQ(signature->version(), SignatureVersion::V3);
}
