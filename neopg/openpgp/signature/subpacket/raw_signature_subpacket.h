// OpenPGP raw signature subpacket
// Copyright 2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#pragma once

#include <neopg/openpgp/signature/signature_subpacket.h>

#include <memory>
#include <vector>

namespace NeoPG {

class NEOPG_UNSTABLE_API RawSignatureSubpacket : public SignatureSubpacket {
 public:
  /// The signature subpacket type.
  SignatureSubpacketType m_type{SignatureSubpacketType::Reserved_0};

  /// The signature subpacket content.
  std::string m_content;

  /// The parser limit for the size of #m_content. Any packet larger than that
  /// will cause a ParserError.
  static const size_t MAX_LENGTH = 2048;

  /// Create new raw signature subpacket from \p input. Throw an exception on
  /// error.
  ///
  /// \param input the parser input to read from
  ///
  /// \return pointer to packet
  ///
  /// \throws ParserError
  static std::unique_ptr<RawSignatureSubpacket> create_or_throw(
      SignatureSubpacketType type, ParserInput& input);

  /// Write the signature subpacket body to the output stream.
  ///
  /// \param out the output stream to write to
  void write_body(std::ostream& out) const override;

  /// \return the subpacket type
  SignatureSubpacketType type() const noexcept override { return m_type; }

  /// Construct a new raw signature subpacket.
  RawSignatureSubpacket() = default;
};

}  // namespace NeoPG
