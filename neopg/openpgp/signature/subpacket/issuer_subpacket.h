// OpenPGP issuer subpacket
// Copyright 2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#pragma once

#include <neopg/openpgp/signature/signature_subpacket.h>

#include <memory>
#include <vector>

namespace NeoPG {

/// Represent an OpenPGP
/// [issuer](https://tools.ietf.org/html/rfc4880#section-5.2.3.5)
/// subpacket.
class NEOPG_UNSTABLE_API IssuerSubpacket : public SignatureSubpacket {
 public:
  /// The issuer key id.
  std::vector<uint8_t> m_issuer;

  /// Create new issuer subpacket from \p input. Throw
  /// an exception on error.
  ///
  /// \param input the parser input to read from
  ///
  /// \return pointer to packet
  ///
  /// \throws ParserError
  static std::unique_ptr<IssuerSubpacket> create_or_throw(ParserInput& input);

  /// Write the signature subpacket body to the output stream.
  ///
  /// \param out the output stream to write to
  void write_body(std::ostream& out) const override;

  /// Return the subpacket type.
  ///
  /// \return the value SignatureSubpacketType::Issuer
  SignatureSubpacketType type() const noexcept override {
    return SignatureSubpacketType::Issuer;
  }

  /// Construct a new issuer subpacket.
  IssuerSubpacket() = default;
};

}  // namespace NeoPG
