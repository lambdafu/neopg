// OpenPGP raw packet (implementation)
// Copyright 2017 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/openpgp/raw_packet.h>

using namespace NeoPG;

void RawPacket::write_body(std::ostream& out) const {
  out.write(m_content.data(), m_content.size());
}

PacketType RawPacket::type() const { return m_packet_type; }
const std::string& RawPacket::content() const { return m_content; };

bool NeoPG::operator==(const RawPacket& p1, const RawPacket& p2) {
  return (p1.type() == p2.type()) && (p1.content() == p2.content());
}
