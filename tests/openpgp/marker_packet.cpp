#include <sstream>

#include "gtest/gtest.h"

#include <neopg/openpgp/marker_packet.h>

#include <memory>

using namespace NeoPG;

TEST(NeoPGTest, openpg_marker_packet_test) {
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
}
