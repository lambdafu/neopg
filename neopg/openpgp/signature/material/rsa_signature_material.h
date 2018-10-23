// OpenPGP rsa signature material
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
/// [RSA signature](https://tools.ietf.org/html/rfc4880#section-5.2.2).
class NEOPG_UNSTABLE_API RsaSignatureMaterial : public SignatureMaterial {
 public:
  /// m**d mod n
  MultiprecisionInteger m_m_pow_d;

  /// Create new rsa signature material from \p input. Throw an exception on
  /// error.
  ///
  /// \param input the parser input to read from
  ///
  /// \return pointer to packet
  ///
  /// \throws ParserError
  static std::unique_ptr<RsaSignatureMaterial> create_or_throw(
      ParserInput& input);

  /// Return the public key algorithm.
  ///
  /// \return the value PublicKeyAlgorithm::Rsa
  PublicKeyAlgorithm algorithm() const override {
    return PublicKeyAlgorithm::Rsa;
  };

  /// Write the signature material to the output stream.
  ///
  /// \param out the output stream to write to
  void write(std::ostream& out) const override;
};

}  // namespace NeoPG
