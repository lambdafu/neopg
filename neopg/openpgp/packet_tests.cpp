// OpenPGP packet (tests)
// Copyright 2017-2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/openpgp/packet_header.h>
#include <neopg/openpgp/literal_data_packet.h>
#include <neopg/openpgp/marker_packet.h>
#include <neopg/openpgp/user_id_packet.h>

#include "gtest/gtest.h"

#include <memory>
#include <sstream>

using namespace NeoPG;

TEST(NeopgTest, openpgp_packet_test) {
  {
    std::stringstream out;
    MarkerPacket packet;

    OldPacketHeader* header = new OldPacketHeader(PacketType::Marker, 3);

    packet.m_header = std::unique_ptr<PacketHeader>(header);
    packet.write(out);
    ASSERT_EQ(out.str(), "\xa8\x03PGP");
  }

  {
    std::stringstream out;
    MarkerPacket packet;
    packet.write(out);
    ASSERT_EQ(out.str(),
              "\xca\x03"
              "PGP");
  }

  {
    std::stringstream out;
    LiteralDataPacket packet;
    packet.write(out);
    ASSERT_EQ(out.str(), std::string("\xCB\x6"
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
    UserIdPacket packet;
    packet.write(out);
    ASSERT_EQ(out.str(), std::string("\xCD\0", 2));
  }

  {
    std::stringstream out;
    UserIdPacket packet;
    packet.m_content = "John Doe john.doe@example.com";
    packet.write(out);
    ASSERT_EQ(out.str(), std::string("\xCD\x1D"
                                     "John Doe john.doe@example.com",
                                     2 + packet.m_content.size()));
  }

  /* Failures.  */
  {
    std::stringstream out;
    LiteralDataPacket packet;
    packet.m_filename = std::string(256, 'A');
    ASSERT_THROW(packet.write(out), std::logic_error);
  }
}
