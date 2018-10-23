// OpenPGP v3 signature data
// Copyright 2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

/// \file
/// This file contains the v3 specific data of signature packets.

#pragma once

#include <neopg/openpgp/signature/signature_data.h>

#include <array>
#include <memory>

namespace NeoPG {

/// Version 3 specific signature data.
class NEOPG_UNSTABLE_API V3SignatureData : public SignatureData {
 public:
  /// The signature type.
  SignatureType m_type{SignatureType::Binary};

  /// The created time of the signature.
  uint32_t m_created{0};

  /// The signer key id.
  std::array<uint8_t, 8> m_signer{{0, 0, 0, 0, 0, 0, 0, 0}};

  /// The public key algorithm of the signature.
  PublicKeyAlgorithm m_public_key_algorithm{PublicKeyAlgorithm::Rsa};

  /// The hash algorithm of the signature.
  HashAlgorithm m_hash_algorithm{HashAlgorithm::Sha1};

  /// The quick check bytes.
  std::array<uint8_t, 2> m_quick{{0, 0}};

  /// The algorithm specific signature material.
  std::unique_ptr<SignatureMaterial> m_signature;

  /// Create new v3 signature data from \p input. Throw an exception on error.
  ///
  /// \param input the parser input to read from
  ///
  /// \return pointer to packet
  ///
  /// \throws ParserError
  static std::unique_ptr<V3SignatureData> create_or_throw(ParserInput& input);

  /// Write the packet body to the output stream.
  ///
  /// \param out the output stream to write to
  void write(std::ostream& out) const override;

  /// Return the signature version.
  ///
  /// \return the value SignatureVersion::V3.
  SignatureVersion version() const noexcept override {
    return SignatureVersion::V3;
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
