// OpenPGP reason for revocation subpacket
// Copyright 2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#pragma once

#include <neopg/openpgp/signature/signature_subpacket.h>

#include <memory>
#include <vector>

namespace NeoPG {

/// Represent an OpenPGP [revocation
/// code](https://tools.ietf.org/html/rfc4880#section-5.2.3.23).
enum class NEOPG_UNSTABLE_API RevocationCode : uint8_t {
  NoReason = 0,
  KeySuperseded = 1,
  KeyCompromised = 2,
  KeyRetired = 3,
  UserIdInvalid = 32,
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

/// Represent an OpenPGP
/// [reason for
/// revocation](https://tools.ietf.org/html/rfc4880#section-5.2.3.23) subpacket.
class NEOPG_UNSTABLE_API ReasonForRevocationSubpacket
    : public SignatureSubpacket {
 public:
  /// The revocation code.
  RevocationCode m_code;

  /// The reason string.
  std::string m_reason;

  /// The parser limit for the size of #m_reason. Any string larger than that
  /// will cause a ParserError.
  static const size_t MAX_LENGTH = 2048;

  /// Create new reason for revocation subpacket from \p input. Throw an
  /// exception on error.
  ///
  /// \param input the parser input to read from
  ///
  /// \return pointer to packet
  ///
  /// \throws ParserError
  static std::unique_ptr<ReasonForRevocationSubpacket> create_or_throw(
      ParserInput& input);

  /// Write the signature subpacket body to the output stream.
  ///
  /// \param out the output stream to write to
  void write_body(std::ostream& out) const override;

  /// Return the subpacket type.
  ///
  /// \return the value SignatureSubpacketType::ReasonForRevocation
  SignatureSubpacketType type() const noexcept override {
    return SignatureSubpacketType::ReasonForRevocation;
  }

  /// Construct a new reason for revocation subpacket.
  ReasonForRevocationSubpacket() = default;
};

}  // namespace NeoPG
