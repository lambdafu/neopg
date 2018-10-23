// OpenPGP RSA public key material
// Copyright 2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

/// \file
/// This file contains the RSA specific key material for public key packets.

#pragma once

#include <neopg/openpgp/public_key/public_key_material.h>

#include <neopg/openpgp/multiprecision_integer.h>
#include <neopg/parser/parser_input.h>

#include <memory>

namespace NeoPG {

/// Key material for RSA public keys.
class NEOPG_UNSTABLE_API RsaPublicKeyMaterial : public PublicKeyMaterial {
 public:
  MultiprecisionInteger m_n;
  MultiprecisionInteger m_e;

  /// Create a new instance from \p input.
  ///
  /// \param input parser input with key material
  ///
  /// Throws ParserError if input can not be parsed.
  static std::unique_ptr<RsaPublicKeyMaterial> create_or_throw(
      ParserInput& input);

  /// Return the public key algorithm.
  ///
  /// \return the value PublicKeyAlgorithm::Rsa
  PublicKeyAlgorithm algorithm() const override {
    return PublicKeyAlgorithm::Rsa;
  };

  /// Write the key material to the output stream.
  ///
  /// \param out the output stream to write to
  void write(std::ostream& out) const override;
};

}  // namespace NeoPG
