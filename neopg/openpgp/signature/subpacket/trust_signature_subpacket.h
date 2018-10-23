// OpenPGP trust signature subpacket
// Copyright 2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#pragma once

#include <neopg/openpgp/signature/signature_subpacket.h>

#include <memory>
#include <vector>

namespace NeoPG {

/// Represent an OpenPGP [trust
/// signature](https://tools.ietf.org/html/rfc4880#section-5.2.3.13) subpacket.
class NEOPG_UNSTABLE_API TrustSignatureSubpacket : public SignatureSubpacket {
 public:
  /// The trust signature level.
  uint8_t m_level;

  /// The trust signature amount.
  uint8_t m_amount;

  /// Create new trust signature subpacket from \p input. Throw an
  /// exception on error.
  ///
  /// \param input the parser input to read from
  ///
  /// \return pointer to packet
  ///
  /// \throws ParserError
  static std::unique_ptr<TrustSignatureSubpacket> create_or_throw(
      ParserInput& input);

  /// Write the signature subpacket body to the output stream.
  ///
  /// \param out the output stream to write to
  void write_body(std::ostream& out) const override;

  /// Return the subpacket type.
  ///
  /// \return the value SignatureSubpacketType::TrustSignature
  SignatureSubpacketType type() const noexcept override {
    return SignatureSubpacketType::TrustSignature;
  }

  /// Construct a new trust signature subpacket.
  TrustSignatureSubpacket() = default;
};

}  // namespace NeoPG
