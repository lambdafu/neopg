// OpenPGP SEIPD packet
// Copyright 2017-2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#pragma once

#include <neopg/openpgp/packet.h>

#include <vector>

namespace NeoPG {

struct NEOPG_UNSTABLE_API SymmetricallyEncryptedIntegrityProtectedDataPacket
    : Packet {
  std::vector<uint8_t> m_data;

  void write_body(std::ostream& out) const override;
  PacketType type() const override;
};

}  // namespace NeoPG
