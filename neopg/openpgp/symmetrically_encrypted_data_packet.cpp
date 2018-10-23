// OpenPGP SED packet (implementation)
// Copyright 2017-2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/openpgp/packet_header.h>
#include <neopg/openpgp/symmetrically_encrypted_data_packet.h>

namespace NeoPG {

void SymmetricallyEncryptedDataPacket::write_body(std::ostream& out) const {
  out.write((char*)m_data.data(), m_data.size());
}

PacketType SymmetricallyEncryptedDataPacket::type() const {
  return PacketType::SymmetricallyEncryptedData;
}

}  // namespace NeoPG
