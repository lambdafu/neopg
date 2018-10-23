// OpenPGP signature material
// Copyright 2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#pragma once

#include <neopg/openpgp/public_key/public_key_material.h>

#include <neopg/parser/parser_input.h>

#include <memory>

namespace NeoPG {

/// Algorithm-specific key material for a
/// [signature](https://tools.ietf.org/html/rfc4880#section-5.2).
class NEOPG_UNSTABLE_API SignatureMaterial {
 public:
  /// Create a new signature material from \p input.
  ///
  /// \param input the parser input to read from
  ///
  /// \return pointer to packet or nullptr on error
  static std::unique_ptr<SignatureMaterial> create_or_throw(
      PublicKeyAlgorithm algorithm, ParserInput& input);

  /// \return the algorithm specifier
  virtual PublicKeyAlgorithm algorithm() const = 0;

  /// Write the key material to the output stream.
  ///
  /// \param out output stream
  virtual void write(std::ostream& out) const = 0;

  // Prevent memory leak when upcasting in smart pointer containers.
  virtual ~SignatureMaterial() = default;
};

}  // namespace NeoPG
