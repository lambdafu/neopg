// OpenPGP ECDH public key material
// Copyright 2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

/// \file
/// This file contains the ECDH specific key material for public key packets.

#pragma once

#include <neopg/openpgp/public_key/public_key_material.h>

#include <neopg/openpgp/multiprecision_integer.h>
#include <neopg/openpgp/object_identifier.h>
#include <neopg/parser/parser_input.h>

#include <memory>

namespace NeoPG {

/// Key material for [Ecdh public
/// keys](https://tools.ietf.org/html/rfc6637#section-9).
class NEOPG_UNSTABLE_API EcdhPublicKeyMaterial : public PublicKeyMaterial {
 public:
  ObjectIdentifier m_curve;
  MultiprecisionInteger m_key;
  uint8_t m_hash;
  uint8_t m_sym;

  /// Create a new instance from \p input.
  ///
  /// \param input parser input with key material
  ///
  /// Throws ParserError if input can not be parsed.
  static std::unique_ptr<EcdhPublicKeyMaterial> create_or_throw(
      ParserInput& input);

  /// Return the public key algorithm.
  ///
  /// \return the value PublicKeyAlgorithm::Ecdh
  PublicKeyAlgorithm algorithm() const override {
    return PublicKeyAlgorithm::Ecdh;
  };

  /// Write the key material to the output stream.
  ///
  /// \param out the output stream to write to
  void write(std::ostream& out) const override;
};

}  // namespace NeoPG
