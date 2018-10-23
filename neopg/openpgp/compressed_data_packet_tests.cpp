// OpenPGP compressed data packet (tests)
// Copyright 2017-2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/openpgp/compressed_data_packet.h>

#include <memory>
#include <sstream>

#include "gtest/gtest.h"

using namespace NeoPG;

TEST(NeopgTest, openpgp_compressed_data_packet_test) {
  {
    std::stringstream out;
    UncompressedDataPacket packet;
    packet.write(out);
    ASSERT_EQ(out.str(), std::string("\xC8\x01"
                                     "\x00",
                                     3));
  }

  {
    std::stringstream out;
    DeflateCompressedDataPacket packet;
    packet.write(out);
    ASSERT_EQ(out.str(), std::string("\xC8\x01"
                                     "\x01",
                                     3));
  }

  {
    std::stringstream out;
    ZlibCompressedDataPacket packet;
    packet.write(out);
    ASSERT_EQ(out.str(), std::string("\xC8\x01"
                                     "\x02",
                                     3));
  }

  {
    std::stringstream out;
    Bzip2CompressedDataPacket packet;
    packet.write(out);
    ASSERT_EQ(out.str(), std::string("\xC8\x01"
                                     "\x03",
                                     3));
  }
}
