// OpenPGP public key packet data
// Copyright 2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

/// \file
/// This file contains the version specific part of public key packets.

#pragma once

#include <neopg/openpgp/packet.h>
#include <neopg/openpgp/public_key/public_key_material.h>

#include <memory>

namespace NeoPG {

/// Represent an OpenPGP [public key
/// version](https://tools.ietf.org/html/rfc4880#section-5.5.2)
enum class PublicKeyVersion : uint8_t { V2 = 2, V3 = 3, V4 = 4 };

/// Represent the version specific part of an OpenPGP [public-key
/// packet](https://tools.ietf.org/html/rfc4880#section-5.5.2).
class NEOPG_UNSTABLE_API PublicKeyData {
 public:
  /// Create new public key data from \p input. Throw an exception on error.
  ///
  /// \param input the parser input to read from
  ///
  /// \return pointer to packet
  ///
  /// \throws ParserError
  static std::unique_ptr<PublicKeyData> create_or_throw(
      PublicKeyVersion version, ParserInput& input);

  /// Write the packet body to the output stream.
  ///
  /// \param out the output stream to write to
  virtual void write(std::ostream& out) const = 0;

  /// Return the public key version.
  virtual PublicKeyVersion version() const noexcept = 0;

  /// Return the public key fingerprint.
  virtual std::vector<uint8_t> fingerprint() const = 0;

  /// Return the public key id.
  virtual std::vector<uint8_t> keyid() const = 0;

  // Prevent memory leak when upcasting in smart pointer containers.
  virtual ~PublicKeyData() = default;
};

}  // namespace NeoPG
