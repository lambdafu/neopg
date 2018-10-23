// OpenPGP literal data packet
// Copyright 2017-2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#pragma once

#include <neopg/openpgp/packet.h>
#include <vector>

namespace NeoPG {

/* FIXME: Replace with function call.  */
const NEOPG_UNSTABLE_API std::string LITERAL_DATA_CONSOLE = "_CONSOLE";

enum class NEOPG_UNSTABLE_API LiteralDataType : uint8_t {
  Binary = 0x62,
  Text = 0x74,
  Utf8 = 0x75,
  Local = 0x6c,
  OldLocal = 0x31,
};

struct NEOPG_UNSTABLE_API LiteralDataPacket : Packet {
  LiteralDataType m_data_type = LiteralDataType::Binary;
  std::string m_filename;
  uint32_t m_timestamp = 0;
  std::vector<uint8_t> m_data;

  void write_body(std::ostream& out) const override;
  PacketType type() const override;
};

}  // namespace NeoPG
