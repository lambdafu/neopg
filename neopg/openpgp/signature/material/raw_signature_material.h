// OpenPGP raw signature material
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
/// [unknown signature](https://tools.ietf.org/html/rfc4880#section-5.2.2).
class NEOPG_UNSTABLE_API RawSignatureMaterial : public SignatureMaterial {
 public:
  /// The algorithm.
  PublicKeyAlgorithm m_algorithm;

  /// The content.
  std::vector<uint8_t> m_content;

  /// The parser limit for the size of #m_content. Any packet larger than that
  /// will cause a ParserError.
  static const size_t MAX_LENGTH = 2048;

  /// Create new raw signature material from \p input. Throw an exception on
  /// error.
  ///
  /// \param algorithm the public key algorithm
  /// \param input the parser input to read from
  ///
  /// \return pointer to packet
  ///
  /// \throws ParserError
  static std::unique_ptr<RawSignatureMaterial> create_or_throw(
      PublicKeyAlgorithm algorithm, ParserInput& input);

  /// Return the public key algorithm.
  ///
  /// \return the algorithm identifier
  PublicKeyAlgorithm algorithm() const override { return m_algorithm; };

  /// Write the signature material to the output stream.
  ///
  /// \param out the output stream to write to
  void write(std::ostream& out) const override;
};

}  // namespace NeoPG
