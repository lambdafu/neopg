#include <sstream>

#include "gtest/gtest.h"

#include <neopg/openpgp/header.h>
#include <neopg/openpgp/literal_data_packet.h>
#include <neopg/openpgp/marker_packet.h>
#include <neopg/openpgp/user_id_packet.h>

#include <memory>

using namespace NeoPG;

TEST(NeoPGTest, openpg_test) {
  {
    std::stringstream out;
    OpenPGP::MarkerPacket packet;

    OpenPGP::OldPacketHeader* header =
        new OpenPGP::OldPacketHeader(OpenPGP::PacketType::Marker, 3);

    packet.m_header = std::unique_ptr<OpenPGP::PacketHeader>(header);
    packet.write(out);
    ASSERT_EQ(out.str(), "\xa8\x03PGP");
  }

  {
    std::stringstream out;
    OpenPGP::MarkerPacket packet;
    packet.write(out);
    ASSERT_EQ(out.str(),
              "\xca\x03"
              "PGP");
  }

  {
    std::stringstream out;
    OpenPGP::LiteralDataPacket packet;
    packet.write(out);
    ASSERT_EQ(out.str(), std::string("\xCB\x6"
                                     "b\0\0\0\0\0",
                                     8));
  }

  {
    std::stringstream out;
    OpenPGP::LiteralDataPacket packet;
    packet.m_filename = "test_test_hello.world";
    packet.write(out);
    ASSERT_EQ(out.str(), std::string("\xCB\x1B"
                                     "b\x15test_test_hello.world\0\0\0\0",
                                     29));
  }

  {
    std::stringstream out;
    OpenPGP::UserIdPacket packet;
    packet.write(out);
    ASSERT_EQ(out.str(), std::string("\xCD\0", 2));
  }

  {
    std::stringstream out;
    OpenPGP::UserIdPacket packet;
    packet.m_content = "John Doe john.doe@example.com";
    packet.write(out);
    ASSERT_EQ(out.str(), std::string("\xCD\x1D"
                                     "John Doe john.doe@example.com",
                                     2 + packet.m_content.size()));
  }

  /* Failures.  */
  {
    std::stringstream out;
    OpenPGP::LiteralDataPacket packet;
    packet.m_filename = std::string(256, 'A');
    ASSERT_THROW(packet.write(out), std::logic_error);
  }
}
