// OpenPGP embedded signature subpacket
// Copyright 2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#pragma once

#include <neopg/openpgp/signature/signature_subpacket.h>

#include <memory>
#include <vector>

namespace NeoPG {

/// Represent an OpenPGP
/// [embedded signature](https://tools.ietf.org/html/rfc4880#section-5.2.3.26)
/// subpacket.
class NEOPG_UNSTABLE_API EmbeddedSignatureSubpacket
    : public SignatureSubpacket {
 public:
  /// The signature content.
  std::vector<uint8_t> m_signature;

  /// The parser limit for the size of #m_signature. Any packet larger
  /// than that will cause a ParserError.
  static const size_t MAX_LENGTH = 2048;

  /// Create new embedded signature subpacket from \p input. Throw
  /// an exception on error.
  ///
  /// \param input the parser input to read from
  ///
  /// \return pointer to packet
  ///
  /// \throws ParserError
  static std::unique_ptr<EmbeddedSignatureSubpacket> create_or_throw(
      ParserInput& input);

  /// Write the signature subpacket body to the output stream.
  ///
  /// \param out the output stream to write to
  void write_body(std::ostream& out) const override;

  /// Return the subpacket type.
  ///
  /// \return the value SignatureSubpacketType::EmbeddedSignature
  SignatureSubpacketType type() const noexcept override {
    return SignatureSubpacketType::EmbeddedSignature;
  }

  /// Construct a new embedded signature subpacket.
  EmbeddedSignatureSubpacket() = default;
};

}  // namespace NeoPG
