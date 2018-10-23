// OpenPGP notation data subpacket
// Copyright 2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#pragma once

#include <neopg/openpgp/signature/signature_subpacket.h>

#include <memory>
#include <vector>

namespace NeoPG {

/// Represent an OpenPGP
/// [notation data](https://tools.ietf.org/html/rfc4880#section-5.2.3.16)
/// subpacket.
class NEOPG_UNSTABLE_API NotationDataSubpacket : public SignatureSubpacket {
 public:
  // Temporary for parsing.
  uint16_t m_length;

  /// The flags (4 octets).
  std::vector<uint8_t> m_flags;

  /// The name.
  std::vector<uint8_t> m_name;

  /// The value.
  std::vector<uint8_t> m_value;

  /// Create new notation data subpacket from \p input. Throw
  /// an exception on error.
  ///
  /// \param input the parser input to read from
  ///
  /// \return pointer to packet
  ///
  /// \throws ParserError
  static std::unique_ptr<NotationDataSubpacket> create_or_throw(
      ParserInput& input);

  /// Write the signature subpacket body to the output stream.
  ///
  /// \param out the output stream to write to
  void write_body(std::ostream& out) const override;

  /// Return the subpacket type.
  ///
  /// \return the value SignatureSubpacketType::NotationData
  SignatureSubpacketType type() const noexcept override {
    return SignatureSubpacketType::NotationData;
  }

  /// Construct a new notation data subpacket.
  NotationDataSubpacket() = default;
};

}  // namespace NeoPG
