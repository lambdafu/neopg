// OpenPGP signature packet
// Copyright 2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

/// \file
/// This file contains support for OpenPGP signature packets.

#pragma once

#include <neopg/openpgp/packet.h>
#include <neopg/openpgp/signature/signature_data.h>

#include <memory>

namespace NeoPG {

/// Represent an OpenPGP [signature
/// packet](https://tools.ietf.org/html/rfc4880#section-5.2).
class NEOPG_UNSTABLE_API SignaturePacket : public Packet {
 public:
  /// Create a new signature packet from \p input.
  ///
  /// \param input the parser input to read from
  ///
  /// \return pointer to packet or nullptr on error
  static std::unique_ptr<SignaturePacket> create_or_throw(ParserInput& input);

  /// Create a new signature packet from \p input. Throw an exception on error.
  ///
  /// \param input the parser input to read from
  ///
  /// \return pointer to packet
  ///
  /// \throws ParserError
  static std::unique_ptr<SignaturePacket> create(ParserInput& input);

  /// The version of the signature packet.
  SignatureVersion m_version{SignatureVersion::V4};

  /// The signature data.
  ///
  /// The signature data has its own version. For example, \a m_version may
  /// indicate a version 2 public key with \a m_public_key being version 3.
  std::unique_ptr<SignatureData> m_signature;

  /// Write the packet body to the output stream.
  ///
  /// \param out the output stream to write to
  void write_body(std::ostream& out) const override;

  /// Return the packet type.
  ///
  /// \return the value PacketType::PublicKey
  PacketType type() const override { return PacketType::Signature; };

  /// Return the signature version of the packet.
  ///
  /// \return the signature version
  SignatureVersion version() const noexcept { return m_version; }

  /// Construct a new signature packet.
  SignaturePacket() = default;
};

}  // namespace NeoPG
