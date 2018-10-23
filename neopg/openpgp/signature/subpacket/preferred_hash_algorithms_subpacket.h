// OpenPGP preferred hash algorithms subpacket
// Copyright 2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#pragma once

#include <neopg/openpgp/signature/signature_subpacket.h>

#include <memory>
#include <vector>

namespace NeoPG {

/// Represent an OpenPGP
/// [preferred hash
/// algorithms](https://tools.ietf.org/html/rfc4880#section-5.2.3.8) subpacket.
class NEOPG_UNSTABLE_API PreferredHashAlgorithmsSubpacket
    : public SignatureSubpacket {
 public:
  /// The signature subpacket content.
  std::vector<uint8_t> m_algorithms;

  /// The parser limit for the size of #m_algorithms. Any packet larger than
  /// that will cause a ParserError.
  static const size_t MAX_LENGTH = 2048;

  /// Create new preferred hash algorithms subpacket from \p input. Throw
  /// an exception on error.
  ///
  /// \param input the parser input to read from
  ///
  /// \return pointer to packet
  ///
  /// \throws ParserError
  static std::unique_ptr<PreferredHashAlgorithmsSubpacket> create_or_throw(
      ParserInput& input);

  /// Write the signature subpacket body to the output stream.
  ///
  /// \param out the output stream to write to
  void write_body(std::ostream& out) const override;

  /// Return the subpacket type.
  ///
  /// \return the value SignatureSubpacketType::PreferredHashAlgorithms
  SignatureSubpacketType type() const noexcept override {
    return SignatureSubpacketType::PreferredHashAlgorithms;
  }

  /// Construct a new preferred hash algorithms subpacket.
  PreferredHashAlgorithmsSubpacket() = default;
};

}  // namespace NeoPG
