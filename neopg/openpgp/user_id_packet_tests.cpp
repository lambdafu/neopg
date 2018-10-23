// OpenPGP user ID packet (tests)
// Copyright 2017-2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/openpgp/user_id_packet.h>

#include <gtest/gtest.h>

#include <memory>
#include <sstream>

using namespace NeoPG;

TEST(OpenpgpUserIdPacket, WriteWithOldHeader) {
  // Test old packet header.
  std::stringstream out;
  UserIdPacket packet;
  packet.write(out);
  ASSERT_EQ(out.str(), std::string("\xCD\0", 2));
}

TEST(OpenpgpUserIdPacket, WriteWithNewHeader) {
  // Test new packet header.
  std::stringstream out;
  UserIdPacket packet;
  packet.m_content = "John Doe john.doe@example.com";
  packet.write(out);
  ASSERT_EQ(out.str(), std::string("\xCD\x1D"
                                   "John Doe john.doe@example.com",
                                   2 + packet.m_content.size()));
}

TEST(OpenpgpUserIdPacket, ParseGood) {
  // Test parser.
  auto uid = std::string{"jonny@example.com"};
  ParserInput in{uid.data(), uid.length()};
  {
    ParserInput::Mark mark(in);
    ASSERT_NO_THROW(UserIdPacket::create_or_throw(in));
    ASSERT_EQ(in.position(), uid.length());
  }

  ASSERT_EQ(in.position(), 0);
  auto packet = UserIdPacket::create_or_throw(in);
  ASSERT_NE(packet, nullptr);
  ASSERT_EQ(packet->m_content, uid);

  // Will never throw, so no failure tests.
}

TEST(OpenpgpUserIdPacket, ParseBad) {
  // Test parser (packet too long)
  const auto uid = std::vector<uint8_t>(UserIdPacket::MAX_LENGTH + 1, 0xff);
  ParserInput in{(const char*)uid.data(), uid.size()};

  ASSERT_ANY_THROW(UserIdPacket::create_or_throw(in));
  ASSERT_EQ(in.position(), (uint32_t)UserIdPacket::MAX_LENGTH);
}
