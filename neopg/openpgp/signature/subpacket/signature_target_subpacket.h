// OpenPGP signature target subpacket
// Copyright 2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#pragma once

#include <neopg/openpgp/signature/signature_subpacket.h>

#include <neopg/openpgp/public_key/public_key_material.h>
#include <neopg/openpgp/signature/signature_data.h>

#include <memory>
#include <vector>

namespace NeoPG {

/// Represent an OpenPGP [signature
/// target](https://tools.ietf.org/html/rfc4880#section-5.2.3.25) subpacket.
class NEOPG_UNSTABLE_API SignatureTargetSubpacket : public SignatureSubpacket {
 public:
  /// The public key algorithm identifier.
  PublicKeyAlgorithm m_public_key_algorithm;

  /// The hash algorithm identifier.
  HashAlgorithm m_hash_algorithm;

  /// The hash.
  std::vector<uint8_t> m_hash;

  /// The parser limit for the size of #m_hash. Any packet larger than that
  /// will cause a ParserError.
  static const size_t MAX_LENGTH = 2048;

  /// Create new signature target subpacket from \p input. Throw an
  /// exception on error.
  ///
  /// \param input the parser input to read from
  ///
  /// \return pointer to packet
  ///
  /// \throws ParserError
  static std::unique_ptr<SignatureTargetSubpacket> create_or_throw(
      ParserInput& input);

  /// Write the signature subpacket body to the output stream.
  ///
  /// \param out the output stream to write to
  void write_body(std::ostream& out) const override;

  /// Return the subpacket type.
  ///
  /// \return the value SignatureSubpacketType::SignatureTarget
  SignatureSubpacketType type() const noexcept override {
    return SignatureSubpacketType::SignatureTarget;
  }

  /// Construct a new signature target subpacket.
  SignatureTargetSubpacket() = default;
};

}  // namespace NeoPG
