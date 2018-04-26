// OpenPGP parser
// Copyright 2017-2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/openpgp.h>

#include <neopg/intern/cplusplus.h>

#include <sstream>

#include "gtest/gtest.h"

using namespace NeoPG;

namespace NeoPG {
std::ostream& operator<<(std::ostream& os, const RawPacket& packet) {
  os << "RawPacket(type=" << (int)packet.type() << ", content=" << packet.content()
     << ")";
  return os;
}
}  // namespace NeoPG

class TestSink : public RawPacketSink {
  std::vector<std::unique_ptr<RawPacket>>& m_packets;

 public:
  TestSink(std::vector<std::unique_ptr<RawPacket>>& packets)
      : m_packets(packets) {}

  void next_packet(std::unique_ptr<PacketHeader> header, const char* data,
                   size_t length) {
    auto packet = NeoPG::make_unique<RawPacket>(header->type(),
                                                std::string(data, length));

    m_packets.emplace_back(std::move(packet));
  }

  void start_packet(std::unique_ptr<PacketHeader> header){};
  void continue_packet(const char* data, size_t length){};
  void finish_packet(std::unique_ptr<NewPacketLength> length_info,
                     const char* data, size_t length){};
};

TEST(NeoPGTest, parser_openpgp_test) {
  {
    std::vector<std::unique_ptr<RawPacket>> packets;
    auto sink = TestSink{packets};
    auto parser = RawPacketParser{sink};

    {
      std::stringstream data;
      auto packet = RawPacket{PacketType::Reserved, "reserved"};
      packet.write(data);

      packets.clear();
      parser.process(data);
      ASSERT_EQ(packets.size(), 1);
      ASSERT_EQ(*packets[0], packet);
    }

    // Missing tests: offset, mixed new/old, partial, indeterminate.
  }
}
