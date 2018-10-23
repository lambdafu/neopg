// OpenPGP v4 public key packet data
// Copyright 2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

/// \file
/// This file contains the version specific part of public key packets.

#pragma once

#include <neopg/openpgp/public_key/public_key_data.h>
#include <neopg/openpgp/public_key/public_key_material.h>

#include <memory>

namespace NeoPG {

class NEOPG_UNSTABLE_API V4PublicKeyData : public PublicKeyData {
 public:
  /// Create new public key data from \p input. Throw an exception on error.
  ///
  /// \param input the parser input to read from
  ///
  /// \return pointer to packet
  ///
  /// \throws ParserError
  static std::unique_ptr<V4PublicKeyData> create_or_throw(ParserInput& input);

  /// The created timestamp.
  uint32_t m_created{0};

  /// The algorithm identifier.
  PublicKeyAlgorithm m_algorithm{PublicKeyAlgorithm::Rsa};

  /// The key material.
  std::unique_ptr<PublicKeyMaterial> m_key;

  /// Write the packet body to the output stream.
  ///
  /// \param out the output stream to write to
  void write(std::ostream& out) const override;

  /// Return the public key version.
  ///
  /// \return the value PublicKeyVersion::V4.
  PublicKeyVersion version() const noexcept override {
    return PublicKeyVersion::V4;
  }

  /// Return the public key fingerprint.
  std::vector<uint8_t> fingerprint() const override;

  /// Return the public key id.
  std::vector<uint8_t> keyid() const override;

  /// Construct new v4 public key packet data.
  V4PublicKeyData() = default;
};

}  // namespace NeoPG
