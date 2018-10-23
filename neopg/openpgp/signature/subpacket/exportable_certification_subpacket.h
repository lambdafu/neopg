// OpenPGP exportable certification subpacket
// Copyright 2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#pragma once

#include <neopg/openpgp/signature/signature_subpacket.h>

#include <memory>
#include <vector>

namespace NeoPG {

/// Represent an OpenPGP [exportable
/// certification](https://tools.ietf.org/html/rfc4880#section-5.2.3.11)
/// subpacket.
class NEOPG_UNSTABLE_API ExportableCertificationSubpacket
    : public SignatureSubpacket {
 public:
  /// The exportable flag.
  uint8_t m_exportable;

  /// Create new exportable certification subpacket from \p input. Throw an
  /// exception on error.
  ///
  /// \param input the parser input to read from
  ///
  /// \return pointer to packet
  ///
  /// \throws ParserError
  static std::unique_ptr<ExportableCertificationSubpacket> create_or_throw(
      ParserInput& input);

  /// Write the signature subpacket body to the output stream.
  ///
  /// \param out the output stream to write to
  void write_body(std::ostream& out) const override;

  /// Return the subpacket type.
  ///
  /// \return the value SignatureSubpacketType::ExportableCertification
  SignatureSubpacketType type() const noexcept override {
    return SignatureSubpacketType::ExportableCertification;
  }

  /// Construct a new exportable certification subpacket.
  ExportableCertificationSubpacket() = default;
};

}  // namespace NeoPG
