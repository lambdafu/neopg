// OpenPGP user ID packet
// Copyright 2017-2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

/// \file
/// This file contains support for OpenPGP user id packets.

#pragma once

#include <neopg/openpgp/packet.h>
#include <neopg/parser/parser_input.h>

#include <vector>

namespace NeoPG {

/// Represent an OpenPGP [user ID
/// packet](https://tools.ietf.org/html/rfc4880#section-5.11).
///
/// User ID packets hold UTF-8 encoded text, often of the form "Name <Email>" or
/// "Name (Comment) <Email>". RFC 4880 does not impose a limit on its length,
/// GnuPG limits it to 2 KB.
class NEOPG_UNSTABLE_API UserIdPacket : public Packet {
 public:
  /// Create a new user ID packet from \p input.
  ///
  /// \param input the parser input to read from
  ///
  /// \return pointer to packet or nullptr on error
  static std::unique_ptr<UserIdPacket> create(ParserInput& input);

  /// Create a new user ID packet from \p input. Throw an exception on error.
  ///
  /// \param input the parser input to read from
  ///
  /// \return pointer to packet
  ///
  /// \throws ParserError
  static std::unique_ptr<UserIdPacket> create_or_throw(ParserInput& input);

  /// The parser limit for the size of #m_content. Any packet larger than that
  /// will cause a ParserError.
  static const size_t MAX_LENGTH = 2048;

  /// The user ID.
  std::string m_content;

  /// Write the packet body to the output stream.
  ///
  /// \param out the output stream to write to
  void write_body(std::ostream& out) const override;

  /// Return the packet type.
  ///
  /// \return the value PacketType::UserId
  PacketType type() const noexcept override { return PacketType::UserId; }

  /// Construct a new trust packet.
  UserIdPacket() = default;
};

}  // namespace NeoPG
