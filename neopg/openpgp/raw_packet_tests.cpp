// OpenPGP raw packet (tests)
// Copyright 2017 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/openpgp/raw_packet.h>

#include <gtest/gtest.h>

#include <memory>
#include <sstream>

using namespace NeoPG;

TEST(NeopgTest, openpgp_raw_packet_test) {
  {
    std::stringstream out;
    RawPacket packet;
    packet.m_data =
        std::vector<uint8_t>{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    packet.write(out);
    ASSERT_EQ(out.str(), std::string("\xCC\x08"
                                     "\x01\x02\x03\x04\x05\x06\x07\x08",
                                     10));
  }
}
