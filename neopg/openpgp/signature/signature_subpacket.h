// OpenPGP signature subpacket
// Copyright 2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#pragma once

#include <neopg/openpgp/packet.h>

#include <memory>
#include <vector>

namespace NeoPG {

/// Represent an OpenPGP [signature subpacket length
/// type](https://tools.ietf.org/html/rfc4880#section-5.2.3.1).
enum class NEOPG_UNSTABLE_API SignatureSubpacketLengthType : uint8_t {
  OneOctet = 0,
  TwoOctet = 1,
  FiveOctet = 2,

  /// This picks the best encoding automatically.
  Default
};

/// Represent an OpenPGP [signature subpacket
/// length](https://tools.ietf.org/html/rfc4880#section-5.2.3.1)
class NEOPG_UNSTABLE_API SignatureSubpacketLength {
 public:
  SignatureSubpacketLengthType m_length_type;
  uint32_t m_length;

  static void verify_length(uint32_t length,
                            SignatureSubpacketLengthType length_type);

  static SignatureSubpacketLengthType best_length_type(uint32_t length);

  void set_length(uint32_t length, SignatureSubpacketLengthType length_type =
                                       SignatureSubpacketLengthType::Default);

  SignatureSubpacketLength(uint32_t length,
                           SignatureSubpacketLengthType length_type =
                               SignatureSubpacketLengthType::Default);

  void write(std::ostream& out);
};

/// Represent an OpenPGP [signature
/// subpacket type](https://tools.ietf.org/html/rfc4880#section-5.2.3.1).
enum class NEOPG_UNSTABLE_API SignatureSubpacketType : uint8_t {
  Reserved_0 = 0,
  Reserved_1 = 1,
  SignatureCreationTime = 2,
  SignatureExpirationTime = 3,
  ExportableCertification = 4,
  TrustSignature = 5,
  RegularExpression = 6,
  Revocable = 7,
  Reserved_8 = 8,
  KeyExpirationTime = 9,
  Placeholder_10 = 10,
  PreferredSymmetricAlgorithms = 11,
  RevocationKey = 12,
  Reserved_13 = 13,
  Reserved_14 = 14,
  Reserved_15 = 15,
  Issuer = 16,
  Reserved_17 = 17,
  Reserved_18 = 18,
  Reserved_19 = 19,
  NotationData = 20,
  PreferredHashAlgorithms = 21,
  PreferredCompressionAlgorithms = 22,
  KeyServerPreferences = 23,
  PreferredKeyServer = 24,
  PrimaryUserId = 25,
  PolicyUri = 26,
  KeyFlags = 27,
  SignersUserId = 28,
  ReasonForRevocation = 29,
  Features = 30,
  SignatureTarget = 31,
  EmbeddedSignature = 32,
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
  // Maximum is 127 (Bit 7 is the "critical" bit).
};

/// Represent an OpenPGP [signature
/// subpacket](https://tools.ietf.org/html/rfc4880#section-5.2.3.1).
class NEOPG_UNSTABLE_API SignatureSubpacket {
 public:
  /// Create new signature subpacket from \p input. Throw an exception on error.
  ///
  /// \param type the signature subpacket type
  /// \param input the parser input to read from
  ///
  /// \return pointer to packet
  ///
  /// \throws ParserError
  static std::unique_ptr<SignatureSubpacket> create_or_throw(
      SignatureSubpacketType type, ParserInput& in);

  /// The critical flag.
  bool m_critical{false};

  /// Use this to overwrite the default length (including the type field).
  std::unique_ptr<SignatureSubpacketLength> m_length;

  /// Write the subpacket to \p out. If \p m_length is set, use that. Otherwise,
  /// generate a default header using the provided length type.
  void write(std::ostream& out,
             SignatureSubpacketLengthType length_type =
                 SignatureSubpacketLengthType::Default) const;

  /// Write the body of the subpacket to \p out.
  ///
  /// @param out The output stream to which the body is written.
  virtual void write_body(std::ostream& out) const = 0;

  /// Return the length of the subpacket.
  uint32_t body_length() const;

  /// Return the subpacket type.
  ///
  /// \return the type of the subpacket.
  virtual SignatureSubpacketType type() const noexcept = 0;

  /// Return the critical flag.
  ///
  /// \return the critical flag
  bool critical() const noexcept { return m_critical; }

  // Prevent memory leak when upcasting in smart pointer containers.
  virtual ~SignatureSubpacket() = default;
};

}  // namespace NeoPG
