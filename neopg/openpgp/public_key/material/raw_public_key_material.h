// OpenPGP raw public key material
// Copyright 2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

/// \file
/// This file contains the raw specific key material for public key packets.

#pragma once

#include <neopg/openpgp/public_key/public_key_material.h>

#include <neopg/openpgp/multiprecision_integer.h>
#include <neopg/parser/parser_input.h>

#include <memory>

namespace NeoPG {

/// Key material for raw public keys.
class NEOPG_UNSTABLE_API RawPublicKeyMaterial : public PublicKeyMaterial {
 public:
  /// The algorithm.
  PublicKeyAlgorithm m_algorithm;

  /// The content.
  std::vector<uint8_t> m_content;

  /// The parser limit for the size of #m_content. Any packet larger than that
  /// will cause a ParserError.
  static const size_t MAX_LENGTH = 2048;

  /// Create a new instance from \p input.
  ///
  /// \param input parser input with key material
  ///
  /// Throws ParserError if input can not be parsed.
  static std::unique_ptr<RawPublicKeyMaterial> create_or_throw(
      PublicKeyAlgorithm algorithm, ParserInput& input);

  /// Return the public key algorithm.
  ///
  /// \return the algorithm identifier
  PublicKeyAlgorithm algorithm() const override { return m_algorithm; };

  /// Write the key material to the output stream.
  ///
  /// \param out the output stream to write to
  void write(std::ostream& out) const override;
};

}  // namespace NeoPG
