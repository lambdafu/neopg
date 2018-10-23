// OpenPGP user attribute packet
// Copyright 2017-2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#pragma once

#include <neopg/openpgp/packet.h>

#include <neopg/openpgp/user_attribute/user_attribute_subpacket.h>

#include <vector>

namespace NeoPG {

/// Representation of an OpenPGP [user
/// attribute](https://tools.ietf.org/html/rfc4880#section-5.12) packet.
class NEOPG_UNSTABLE_API UserAttributePacket : public Packet {
 public:
  /// The subpackets.
  std::vector<std::unique_ptr<UserAttributeSubpacket>> m_subpackets;

  /// Create a new user attribute packet from \p input.
  ///
  /// \param input the parser input to read from
  ///
  /// \return pointer to packet or nullptr on error
  static std::unique_ptr<UserAttributePacket> create(ParserInput& input);

  /// Create a new user attribute packet from \p input. Throw an exception on
  /// error.
  ///
  /// \param input the parser input to read from
  ///
  /// \return pointer to packet
  ///
  /// \throws ParserError
  static std::unique_ptr<UserAttributePacket> create_or_throw(
      ParserInput& input);

  /// Write the packet body to the output stream.
  ///
  /// \param out the output stream to write to
  void write_body(std::ostream& out) const override;

  /// Return the packet type.
  ///
  /// \return the value PacketType::UserAttribute
  PacketType type() const noexcept override {
    return PacketType::UserAttribute;
  }
};

}  // namespace NeoPG
