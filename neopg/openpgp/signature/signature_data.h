// OpenPGP signature data
// Copyright 2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

/// \file
/// This file contains the version specific part of a signature packet.

#pragma once

#include <neopg/openpgp/packet.h>
#include <neopg/openpgp/public_key/public_key_material.h>
#include <neopg/openpgp/signature/signature_material.h>

#include <memory>

namespace NeoPG {

/// Represent an OpenPGP [hash
/// algorithm](https://tools.ietf.org/html/rfc4880#section-9.4).
enum class HashAlgorithm : uint8_t {
  Md5 = 1,
  Sha1 = 2,
  Ripemd160 = 3,
  Reserved_4 = 4,
  Reserved_5 = 5,
  Reserved_6 = 6,
  Reserved_7 = 7,
  Sha256 = 8,
  Sha384 = 9,
  Sha512 = 10,
  Sha224 = 11,
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

/// Represent an OpenPGP [signature
/// version](https://tools.ietf.org/html/rfc4880#section-5.2)
enum class SignatureVersion : uint8_t { V2 = 2, V3 = 3, V4 = 4 };

/// Represent an OpenPGP [signature
/// type](https://tools.ietf.org/html/rfc4880#section-5.2.1).
enum class NEOPG_UNSTABLE_API SignatureType : uint8_t {
  Binary = 0x00,
  Text = 0x01,
  Standalone = 0x02,
  UidGeneric = 0x10,
  UidPersona = 0x11,
  UidCasual = 0x12,
  UidPositive = 0x13,
  BindingSubkey = 0x18,
  BindingKey = 0x19,
  KeyDirect = 0x1f,
  RevokeKey = 0x20,
  RevokeSubkey = 0x28,
  RevokeUid = 0x30,
  Timestamp = 0x40,
  Confirmation = 0x50
};

/// Represent an OpenPGP [signature
/// packet](https://tools.ietf.org/html/rfc4880#section-5.2).
class NEOPG_UNSTABLE_API SignatureData {
 public:
  /// Create new signature data from \p input. Throw an exception on error.
  ///
  /// \param input the parser input to read from
  ///
  /// \return pointer to packet
  ///
  /// \throws ParserError
  static std::unique_ptr<SignatureData> create_or_throw(
      SignatureVersion version, ParserInput& input);

  /// Write the packet body to the output stream.
  ///
  /// \param out the output stream to write to
  virtual void write(std::ostream& out) const = 0;

  /// Return the signature version.
  virtual SignatureVersion version() const noexcept = 0;

  // Prevent memory leak when upcasting in smart pointer containers.
  virtual ~SignatureData() = default;
};

}  // namespace NeoPG
