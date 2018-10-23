// OpenPGP literal data packet (tests)
// Copyright 2017-2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/openpgp/literal_data_packet.h>

#include "gtest/gtest.h"

#include <memory>
#include <sstream>

using namespace NeoPG;

TEST(NeopgTest, openpgp_literal_data_packet_test) {
  {
    std::stringstream out;
    LiteralDataPacket packet;
    packet.write(out);
    ASSERT_EQ(out.str(), std::string("\xCB\x06"
                                     "b\0\0\0\0\0",
                                     8));
  }

  {
    std::stringstream out;
    LiteralDataPacket packet;
    packet.m_filename = "test_test_hello.world";
    packet.write(out);
    ASSERT_EQ(out.str(), std::string("\xCB\x1B"
                                     "b\x15test_test_hello.world\0\0\0\0",
                                     29));
  }

  {
    std::stringstream out;
    LiteralDataPacket packet;
    packet.m_timestamp = 0x12345678;
    packet.write(out);
    ASSERT_EQ(out.str(), std::string("\xCB\x06"
                                     "b\0\x12\x34\x56\x78",
                                     8));
  }

  {
    std::stringstream out;
    LiteralDataPacket packet;
    packet.m_data_type = LiteralDataType::Text;
    packet.write(out);
    ASSERT_EQ(out.str(), std::string("\xCB\x06"
                                     "t\0\0\0\0\0",
                                     8));
  }

  /* Failures.  */
  {
    std::stringstream out;
    LiteralDataPacket packet;
    packet.m_filename = std::string(256, 'A');
    ASSERT_THROW(packet.write(out), std::logic_error);
  }
}
