// OpenPGP v4 signature subpacket data
// Copyright 2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

/// \file
/// This file contains the v4 specific data of signature subpacket data.

#pragma once

#include <neopg/openpgp/signature/signature_subpacket.h>

#include <array>
#include <memory>

namespace NeoPG {

/// Signature subpackets as found in version 4 signature data.
class NEOPG_UNSTABLE_API V4SignatureSubpacketData {
 public:
  /// The signature subpackets.
  std::vector<std::unique_ptr<SignatureSubpacket>> m_subpackets;

  /// Create new v4 signature subpacket data from \p input. Throw an exception
  /// on error.
  ///
  /// \param input the parser input to read from
  ///
  /// \return pointer to packet
  ///
  /// \throws ParserError
  static std::unique_ptr<V4SignatureSubpacketData> create_or_throw(
      ParserInput& input);

  /// Write the signature subpacket data to the output stream.
  ///
  /// \param out the output stream to write to
  void write(std::ostream& out) const;
};

}  // namespace NeoPG
