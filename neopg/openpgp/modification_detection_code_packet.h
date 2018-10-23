// OpenPGP MDC packet
// Copyright 2017-2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

/// \file
/// This file contains support for OpenPGP MDC packets.

#pragma once

#include <neopg/openpgp/packet.h>
#include <neopg/parser/parser_input.h>

#include <array>
#include <memory>

namespace NeoPG {

/// Represent an OpenPGP [modification detection code
/// packet](https://tools.ietf.org/html/rfc4880#section-5.14).
///
/// MDC packets add integrity to RFC 4880 encryption.  RFC 4880 requires that
/// the MDC is 20-bytes (::write_body throws a logic_error exception if that is
/// not true). It also requires that the packet uses a NewPacketHeader with
/// PacketLengthType::OneOctet (this is not enforced by this class, but it is
/// the default behaviour).
struct NEOPG_UNSTABLE_API ModificationDetectionCodePacket : Packet {
  /// Create a new mdc packet from \p input.
  ///
  /// \param input the parser input to read from
  ///
  /// \return pointer to packet or nullptr on error
  static std::unique_ptr<ModificationDetectionCodePacket> create(
      ParserInput& input);

  /// Create a new mdc packet from \p input. Throw an exception on error.
  ///
  /// \param input the parser input to read from
  ///
  /// \return pointer to packet
  ///
  /// \throws ParserError
  static std::unique_ptr<ModificationDetectionCodePacket> create_or_throw(
      ParserInput& input);

  /// The length of an MDC.
  static const size_t LENGTH = 20;

  /// The MDC data.
  std::array<uint8_t, LENGTH> m_mdc;

  /// Write the packet body to the output stream.
  ///
  /// \param out the output stream to write to
  void write_body(std::ostream& out) const override;

  /// Return the packet type.
  ///
  /// \return the value PacketType::ModificationDetectionCode
  PacketType type() const noexcept override {
    return PacketType::ModificationDetectionCode;
  }

  /// Construct a new trust packet.
  ModificationDetectionCodePacket() = default;
};

}  // namespace NeoPG
