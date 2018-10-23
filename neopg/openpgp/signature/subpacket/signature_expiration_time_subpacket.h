// OpenPGP signature expiration time subpacket
// Copyright 2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#pragma once

#include <neopg/openpgp/signature/signature_subpacket.h>

#include <memory>
#include <vector>

namespace NeoPG {

/// Represent an OpenPGP [signature expiration
/// time](https://tools.ietf.org/html/rfc4880#section-5.2.3.10) subpacket.
class NEOPG_UNSTABLE_API SignatureExpirationTimeSubpacket
    : public SignatureSubpacket {
 public:
  /// The signature expiration time.
  uint32_t m_expiration;

  /// Create new signature expiration time subpacket from \p input. Throw an
  /// exception on error.
  ///
  /// \param input the parser input to read from
  ///
  /// \return pointer to packet
  ///
  /// \throws ParserError
  static std::unique_ptr<SignatureExpirationTimeSubpacket> create_or_throw(
      ParserInput& input);

  /// Write the signature subpacket body to the output stream.
  ///
  /// \param out the output stream to write to
  void write_body(std::ostream& out) const override;

  /// Return the subpacket type.
  ///
  /// \return the value SignatureSubpacketType::SignatureExpirationTime
  SignatureSubpacketType type() const noexcept override {
    return SignatureSubpacketType::SignatureExpirationTime;
  }

  /// Construct a new signature expiration time subpacket.
  SignatureExpirationTimeSubpacket() = default;
};

}  // namespace NeoPG
