// OpenPGP public subkey packet
// Copyright 2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

/// \file
/// This file contains support for OpenPGP public key packets.

#pragma once

#include <neopg/openpgp/packet.h>
#include <neopg/openpgp/public_key/public_key_data.h>

#include <memory>

namespace NeoPG {

/// Represent an OpenPGP [public-subkey
/// packet](https://tools.ietf.org/html/rfc4880#section-5.5.2).
class NEOPG_UNSTABLE_API PublicSubkeyPacket : public Packet {
 public:
  /// Create a new public subkey packet from \p input.
  ///
  /// \param input the parser input to read from
  ///
  /// \return pointer to packet or nullptr on error
  static std::unique_ptr<PublicSubkeyPacket> create_or_throw(
      ParserInput& input);

  /// Create a new public subkey packet from \p input. Throw an exception on
  /// error.
  ///
  /// \param input the parser input to read from
  ///
  /// \return pointer to packet
  ///
  /// \throws ParserError
  static std::unique_ptr<PublicSubkeyPacket> create(ParserInput& input);

  /// The version of the public key packet.
  PublicKeyVersion m_version{PublicKeyVersion::V4};

  /// The public key data.
  ///
  /// The public key data has its own version. For example, \a m_version may
  /// indicate a version 2 public key with \a m_public_key being version 3.
  std::unique_ptr<PublicKeyData> m_public_key;

  /// Write the packet body to the output stream.
  ///
  /// \param out the output stream to write to
  void write_body(std::ostream& out) const override;

  /// Return the packet type.
  ///
  /// \return the value PacketType::PublicKey
  PacketType type() const noexcept override {
    return PacketType::PublicSubkey;
  };

  /// Return the public subkey version of the packet.
  ///
  /// \return the public subkey version
  PublicKeyVersion version() const noexcept { return m_version; }

  /// Construct a new public subkey packet.
  PublicSubkeyPacket() = default;
};

}  // namespace NeoPG
