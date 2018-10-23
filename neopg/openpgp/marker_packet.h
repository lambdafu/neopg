// OpenPGP marker packet
// Copyright 2017-2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

/// \file
/// This file contains support for OpenPGP marker packets.

#pragma once

#include <neopg/openpgp/packet.h>
#include <neopg/parser/parser_input.h>

#include <memory>

namespace NeoPG {

/// Represent an OpenPGP [marker
/// packet](https://tools.ietf.org/html/rfc4880#section-5.8).
///
/// Marker packets are obsolete. They are provided
/// here for completeness.
///
/// This implementation only supports the official marker ("PGP"). If you need a
/// different marker packet, use a RawPacket instead.
class NEOPG_UNSTABLE_API MarkerPacket : public Packet {
 public:
  /// Create a new marker packet from \p input.
  ///
  /// \param input the parser input to read from
  ///
  /// \return pointer to packet or nullptr on error
  static std::unique_ptr<MarkerPacket> create(ParserInput& input);

  /// Create a new marker packet from \p input. Throw an exception on error.
  ///
  /// \param input the parser input to read from
  ///
  /// \return pointer to packet
  ///
  /// \throws ParserError
  static std::unique_ptr<MarkerPacket> create_or_throw(ParserInput& input);

  /// Write the packet body to the output stream.
  ///
  /// \param out the output stream to write to
  void write_body(std::ostream& out) const override;

  /// Return the packet type.
  ///
  /// \return the value PacketType::Marker
  PacketType type() const noexcept override { return PacketType::Marker; }

  /// Construct a new marker packet.
  MarkerPacket() = default;
};

}  // namespace NeoPG
