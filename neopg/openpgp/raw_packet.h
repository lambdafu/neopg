// OpenPGP format
// Copyright 2017 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#pragma once

#include <neopg/openpgp/packet.h>
#include <neopg/openpgp/packet_header.h>

namespace NeoPG {

class NEOPG_UNSTABLE_API RawPacket : public Packet {
  PacketType m_packet_type{NeoPG::PacketType::Reserved};
  std::string m_content;

 public:
  RawPacket(PacketType packet_type, std::string content = "")
      : m_packet_type(packet_type), m_content(content) {}
  void write_body(std::ostream& out) const override;
  PacketType type() const override;
  const std::string& content() const;
};

NEOPG_UNSTABLE_API bool operator==(const RawPacket& p1, const RawPacket& p2);

}  // namespace NeoPG
