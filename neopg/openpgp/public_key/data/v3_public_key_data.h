// OpenPGP public key packet data v3
// Copyright 2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

/// \file
/// This file contains the version 3 specific part of public key packets.

#pragma once

#include <neopg/openpgp/public_key/public_key_data.h>

namespace NeoPG {

class NEOPG_UNSTABLE_API V3PublicKeyData : public PublicKeyData {
 public:
  /// Create new public key data from \p input. Throw an exception on error.
  ///
  /// \param input the parser input to read from
  ///
  /// \return pointer to packet
  ///
  /// \throws ParserError
  static std::unique_ptr<V3PublicKeyData> create_or_throw(ParserInput& input);

  /// The created timestamp.
  uint32_t m_created{0};

  /// The number of days until expiration.
  uint16_t m_days_valid{0};

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
  /// \return the value PublicKeyVersion::V3.
  PublicKeyVersion version() const noexcept override {
    return PublicKeyVersion::V3;
  }

  /// Return the public key fingerprint.
  std::vector<uint8_t> fingerprint() const override;

  /// The length of the keyid (8).
  static constexpr size_t KEYID_LENGTH{8};

  /// Return the public key id. Can return a truncated string if the RSA
  /// parameter n is too short for a complete key id.
  std::vector<uint8_t> keyid() const override;

  /// Construct new v3 public key packet data.
  V3PublicKeyData() = default;
};

}  // namespace NeoPG
