// OpenPGP eddsa signature material
// Copyright 2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#pragma once

#include <neopg/openpgp/signature/signature_material.h>

#include <neopg/openpgp/multiprecision_integer.h>
#include <neopg/parser/parser_input.h>

#include <memory>

namespace NeoPG {

/// Algorithm-specific key material for a
/// [EdDSA
/// signature](https://www.ietf.org/archive/id/draft-koch-eddsa-for-openpgp-04.txt).

/// Key material for EdDSA public keys.
class NEOPG_UNSTABLE_API EddsaSignatureMaterial : public SignatureMaterial {
 public:
  /// The value r.
  MultiprecisionInteger m_r;

  /// The value s.
  MultiprecisionInteger m_s;

  /// Create new eddsa signature material from \p input. Throw an exception on
  /// error.
  ///
  /// \param input the parser input to read from
  ///
  /// \return pointer to packet
  ///
  /// \throws ParserError
  static std::unique_ptr<EddsaSignatureMaterial> create_or_throw(
      ParserInput& input);

  /// Return the public key algorithm.
  ///
  /// \return the value PublicKeyAlgorithm::Eddsa
  PublicKeyAlgorithm algorithm() const override {
    return PublicKeyAlgorithm::Eddsa;
  };

  /// Write the signature material to the output stream.
  ///
  /// \param out the output stream to write to
  void write(std::ostream& out) const override;
};

}  // namespace NeoPG
