// OpenPGP trust packet
// Copyright 2017-2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

/// \file
/// This file contains support for OpenPGP trust packets.

#pragma once

#include <neopg/openpgp/packet.h>
#include <neopg/parser/parser_input.h>

#include <vector>

namespace NeoPG {

/// Represent an OpenPGP [trust
/// packet](https://tools.ietf.org/html/rfc4880#section-5.10).
///
/// Trust packets are for internal use only (but NeoPG does not use them). They
/// are provided here for completeness.
class NEOPG_UNSTABLE_API TrustPacket : public Packet {
 public:
  /// Create a new trust packet from \p input.
  ///
  /// \param input the parser input to read from
  ///
  /// \return pointer to packet or nullptr on error
  static std::unique_ptr<TrustPacket> create(ParserInput& input);

  /// Create a new trust packet from \p input. Throw an exception on error.
  ///
  /// \param input the parser input to read from
  ///
  /// \return pointer to packet
  ///
  /// \throws ParserError
  static std::unique_ptr<TrustPacket> create_or_throw(ParserInput& input);

  /// The parser limit for the size of #m_data. Any packet larger than that will
  /// cause a ParserError.
  static const size_t MAX_LENGTH{2048};

  /// The (raw) content of the trust packet.
  std::vector<uint8_t> m_data;

  /// Write the packet body to the output stream.
  ///
  /// \param out the output stream to write to
  void write_body(std::ostream& out) const override;

  /// Return the packet type.
  ///
  /// \return the value PacketType::Trust
  PacketType type() const noexcept override { return PacketType::Trust; }

  /// Construct a new trust packet.
  TrustPacket() = default;
};

}  // namespace NeoPG
