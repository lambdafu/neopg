// OpenPGP revocation key subpacket
// Copyright 2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#pragma once

#include <neopg/signature_subpacket.h>

#include <neopg/public_key_material.h>

#include <memory>
#include <vector>

namespace NeoPG {

/// Represent an OpenPGP [revocation
/// key](https://tools.ietf.org/html/rfc4880#section-5.2.3.15) subpacket.
class NEOPG_UNSTABLE_API RevocationKeySubpacket : public SignatureSubpacket {
 public:
  /// The class.
  uint8_t m_class;

  /// The public key algorithm identifier.
  PublicKeyAlgorithm m_algorithm;

  /// The fingerprint.
  std::vector<uint8_t> m_fingerprint;

  /// Create new revocation key subpacket from \p input. Throw an
  /// exception on error.
  ///
  /// \param input the parser input to read from
  ///
  /// \return pointer to packet
  ///
  /// \throws ParserError
  static std::unique_ptr<RevocationKeySubpacket> create_or_throw(
      ParserInput& input);

  /// Write the signature subpacket body to the output stream.
  ///
  /// \param out the output stream to write to
  void write_body(std::ostream& out) const override;

  /// Return the subpacket type.
  ///
  /// \return the value SignatureSubpacketType::RevocationKey
  SignatureSubpacketType type() const noexcept override {
    return SignatureSubpacketType::RevocationKey;
  }

  /// Construct a new revocation key subpacket.
  RevocationKeySubpacket() = default;
};

}  // namespace NeoPG
