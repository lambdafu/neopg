// OpenPGP ecdsa signature material
// Copyright 2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#pragma once

#include <neopg/openpgp/signature/signature_material.h>

#include <neopg/openpgp/multiprecision_integer.h>
#include <neopg/parser/parser_input.h>

#include <memory>

namespace NeoPG {

/// Algorithm-specific key material for an
/// [ECDSA signature](https://tools.ietf.org/html/rfc6637#section-10).
class NEOPG_UNSTABLE_API EcdsaSignatureMaterial : public SignatureMaterial {
 public:
  /// The value r.
  MultiprecisionInteger m_r;

  /// The value s.
  MultiprecisionInteger m_s;

  /// Create new ecdsa signature material from \p input. Throw an exception on
  /// error.
  ///
  /// \param input the parser input to read from
  ///
  /// \return pointer to packet
  ///
  /// \throws ParserError
  static std::unique_ptr<EcdsaSignatureMaterial> create_or_throw(
      ParserInput& input);

  /// Return the public key algorithm.
  ///
  /// \return the value PublicKeyAlgorithm::Ecdsa
  PublicKeyAlgorithm algorithm() const override {
    return PublicKeyAlgorithm::Ecdsa;
  };

  /// Write the signature material to the output stream.
  ///
  /// \param out the output stream to write to
  void write(std::ostream& out) const override;
};

}  // namespace NeoPG
