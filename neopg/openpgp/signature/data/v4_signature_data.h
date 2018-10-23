// OpenPGP v4 signature data
// Copyright 2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

/// \file
/// This file contains the v4 specific data of signature packets.

#pragma once

#include <neopg/openpgp/signature/signature_data.h>
#include <neopg/openpgp/signature/data/v4_signature_subpacket_data.h>

#include <array>
#include <memory>

namespace NeoPG {

/// Version 4 specific signature data.
class NEOPG_UNSTABLE_API V4SignatureData : public SignatureData {
 public:
  /// The signature type.
  SignatureType m_type{SignatureType::Binary};

  /// The created time of the signature.
  uint32_t m_created{0};

  /// The public key algorithm of the signature.
  PublicKeyAlgorithm m_public_key_algorithm{PublicKeyAlgorithm::Rsa};

  /// The hash algorithm of the signature.
  HashAlgorithm m_hash_algorithm{HashAlgorithm::Sha1};

  /// The algorithm specific signature material.
  std::unique_ptr<SignatureMaterial> m_signature;

  /// The hashed signature subpackets.
  std::unique_ptr<V4SignatureSubpacketData> m_hashed_subpackets;

  /// The unhashed signature subpackets.
  std::unique_ptr<V4SignatureSubpacketData> m_unhashed_subpackets;

  /// The quick check bytes.
  std::array<uint8_t, 2> m_quick{{0, 0}};

  /// Create new v4 signature data from \p input. Throw an exception on error.
  ///
  /// \param input the parser input to read from
  ///
  /// \return pointer to packet
  ///
  /// \throws ParserError
  static std::unique_ptr<V4SignatureData> create_or_throw(ParserInput& input);

  /// Write the v4 signature data to the output stream.
  ///
  /// \param out the output stream to write to
  void write(std::ostream& out) const override;

  /// Return the signature version.
  ///
  /// \return the value SignatureVersion::V4.
  SignatureVersion version() const noexcept override {
    return SignatureVersion::V4;
  }

  /// \return the signature type
  SignatureType signature_type() const noexcept { return m_type; }

  /// \return the public key algorithm
  PublicKeyAlgorithm public_key_algorithm() const noexcept {
    return m_public_key_algorithm;
  }

  /// \return the hash algorithm
  HashAlgorithm hash_algorithm() const noexcept { return m_hash_algorithm; }
};

}  // namespace NeoPG
