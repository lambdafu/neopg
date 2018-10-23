// OpenPGP public key material
// Copyright 2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

/// \file
/// This file contains the algorithm specific key material of public key
/// packets.

#pragma once

#include <neopg/openpgp/multiprecision_integer.h>
#include <neopg/openpgp/object_identifier.h>
#include <neopg/parser/parser_input.h>

#include <memory>

namespace NeoPG {

/// Public key [algorithm
/// specifier](https://tools.ietf.org/html/rfc4880#section-9.1).
enum class PublicKeyAlgorithm : uint8_t {
  Rsa = 1,
  RsaEncrypt = 2,
  RsaSign = 3,
  ElgamalEncrypt = 16,
  Dsa = 17,
  Ecdh = 18,
  Ecdsa = 19,
  Elgamal = 20,
  DhX942 = 21,
  Eddsa = 22,
  Private_100 = 100,
  Private_101 = 101,
  Private_102 = 102,
  Private_103 = 103,
  Private_104 = 104,
  Private_105 = 105,
  Private_106 = 106,
  Private_107 = 107,
  Private_108 = 108,
  Private_109 = 109,
  Private_110 = 110
};

/// Algorithm-specific key material for a [public
/// key](https://tools.ietf.org/html/rfc4880#section-5.5.2).
class NEOPG_UNSTABLE_API PublicKeyMaterial {
 public:
  /// Create an instance based on the algorithm.
  ///
  /// \param algorithm algorithm specifier
  /// \param input parser input with key material
  ///
  /// Throws ParserError if input can not be parsed.
  static std::unique_ptr<PublicKeyMaterial> create_or_throw(
      PublicKeyAlgorithm algorithm, ParserInput& input);

  /// \return the algorithm specifier
  virtual PublicKeyAlgorithm algorithm() const = 0;

  /// Write the key material to the output stream.
  ///
  /// \param out output stream
  virtual void write(std::ostream& out) const = 0;

  // Prevent memory leak when upcasting in smart pointer containers.
  virtual ~PublicKeyMaterial() = default;
};

}  // namespace NeoPG
