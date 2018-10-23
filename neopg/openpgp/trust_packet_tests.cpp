// OpenPGP trust packet (tests)
// Copyright 2017-2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/openpgp/trust_packet.h>

#include <gtest/gtest.h>

#include <memory>
#include <sstream>

using namespace NeoPG;

TEST(OpenpgpTrustPacket, WriteWithNewHeader) {
  std::stringstream out;
  TrustPacket packet;
  packet.m_data =
      std::vector<uint8_t>{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
  packet.write(out);
  ASSERT_EQ(out.str(), std::string("\xCC\x08"
                                   "\x01\x02\x03\x04\x05\x06\x07\x08",
                                   10));
}

TEST(OpenpgpTrustPacket, ParseGood) {
  // Test parser.
  const auto trust = std::vector<uint8_t>{0x01, 0x02, 0x03, 0x04};
  ParserInput in{(const char*)trust.data(), trust.size()};

  {
    ParserInput::Mark mark(in);
    ASSERT_NO_THROW(TrustPacket::create_or_throw(in));
    ASSERT_EQ(in.position(), trust.size());
  }
  ASSERT_EQ(in.position(), 0);
  auto packet = TrustPacket::create(in);
  ASSERT_NE(packet, nullptr);
  ASSERT_EQ(packet->m_data, trust);
}

TEST(OpenpgpTrustPacket, ParseBad) {
  // Test parser (packet too long)
  const auto trust = std::vector<uint8_t>(TrustPacket::MAX_LENGTH + 1, 0xff);
  ParserInput in{(const char*)trust.data(), trust.size()};

  ASSERT_ANY_THROW(TrustPacket::create_or_throw(in));
  ASSERT_EQ(in.position(), (uint32_t)TrustPacket::MAX_LENGTH);
}
