// OpenPGP packet header
// Copyright 2017-2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#pragma once

#include <neopg/utils/common.h>

#include <cstdint>
#include <iostream>
#include <memory>
#include <stdexcept>

namespace NeoPG {

/// Represent an OpenPGP [packet
/// type](https://tools.ietf.org/html/rfc4880#section-4.3).
enum class NEOPG_UNSTABLE_API PacketType : uint8_t {
  Reserved = 0,                      ///< Reserved (use RawPacket)
  PublicKeyEncryptedSessionKey = 1,  ///< PublicKeyEncryptedSessionKeyPacket
  Signature = 2,                     ///< SignaturePacket
  SymmetricKeyEncryptedSessionKey =
      3,                           ///< SymmetricKeyEncryptedSessionKeyPacket
  OnePassSignature = 4,            ///< OnePassSignaturePacket
  SecretKey = 5,                   ///< SecretKeyPacket
  PublicKey = 6,                   ///< PublicKeyPacket
  SecretSubkey = 7,                ///< SecretSubkeyPacket
  CompressedData = 8,              ///< CompressedDataPacket
  SymmetricallyEncryptedData = 9,  ///< SymmetricallyEncryptedDataPacket
  Marker = 10,                     ///< MarkerPacket
  LiteralData = 11,                ///< LiteralDataPacket
  Trust = 12,                      ///< TrustPacket
  UserId = 13,                     ///< UserIdPacket
  PublicSubkey = 14,               ///< PublicSubkeyPacket
  UserAttribute = 17,              ///< UserAttributePacket
  SymmetricallyEncryptedIntegrityProtectedData =
      18,  ///< SymmetricallyEncryptedIntegrityProtectedDataPacket
  ModificationDetectionCode = 19,  ///< ModificationDetectionCodePacket
  Private_60 = 60,  ///< Private or Experimental Value (use RawPaceket)
  Private_61 = 61,  ///< Private or Experimental Value (use RawPaceket)
  Private_62 = 62,  ///< Private or Experimental Value (use RawPaceket)
  Private_63 = 63,  ///< Private or Experimental Value (use RawPaceket)
};

enum class NEOPG_UNSTABLE_API PacketLengthType : uint8_t {
  OneOctet = 0,
  TwoOctet = 1,

  // New packet format
  FiveOctet = 2,
  Partial = 3,

  // Old packet format
  FourOctet = 2,
  Indeterminate = 3,

  /// This picks the best encoding automatically.
  Default
};

/// Represent an OpenPGP packet header.
struct NEOPG_UNSTABLE_API PacketHeader {
 public:
  size_t m_offset;

  virtual void write(std::ostream& out) const = 0;
  virtual PacketType type() const = 0;

  virtual uint32_t length() const = 0;

  // Prevent memory leak when upcasting in smart pointer containers.
  virtual ~PacketHeader() = default;
};

class NEOPG_UNSTABLE_API OldPacketHeader : public PacketHeader {
 public:
  PacketType m_packet_type;
  PacketLengthType m_length_type;
  uint32_t m_length;

  static std::unique_ptr<OldPacketHeader> create_or_throw(PacketType type,
                                                          uint32_t length);

  static void verify_length(uint32_t length, PacketLengthType length_type);

  static PacketLengthType best_length_type(uint32_t length);

  OldPacketHeader(PacketType packet_type, uint32_t length,
                  PacketLengthType length_type = PacketLengthType::Default);

  void set_packet_type(PacketType packet_type);

  void set_length(uint32_t length,
                  PacketLengthType length_type = PacketLengthType::Default);

  void write(std::ostream& out) const override;

  PacketType type() const override { return m_packet_type; }
  uint32_t length() const override { return m_length; }
};

class NEOPG_UNSTABLE_API NewPacketTag {
 public:
  PacketType m_packet_type;

  void set_packet_type(PacketType packet_type);

  NewPacketTag(PacketType packet_type);

  void write(std::ostream& out) const;
};

class NEOPG_UNSTABLE_API NewPacketLength {
 public:
  PacketLengthType m_length_type;
  uint32_t m_length;

  static void verify_length(uint32_t length, PacketLengthType length_type);

  static PacketLengthType best_length_type(uint32_t length);

  void set_length(uint32_t length,
                  PacketLengthType length_type = PacketLengthType::Default);

  NewPacketLength(uint32_t length,
                  PacketLengthType length_type = PacketLengthType::Default);

  void write(std::ostream& out) const;
};

class NEOPG_UNSTABLE_API NewPacketHeader : public PacketHeader {
 public:
  NewPacketTag m_tag;
  NewPacketLength m_length;

  static std::unique_ptr<NewPacketHeader> create_or_throw(PacketType type,
                                                          uint32_t length);

  NewPacketHeader(NewPacketTag tag, NewPacketLength length)
      : m_tag(tag), m_length(length) {}

  NewPacketHeader(PacketType packet_type, uint32_t length,
                  PacketLengthType length_type = PacketLengthType::Default)
      : m_tag(packet_type), m_length(length, length_type) {}

  void write(std::ostream& out) const override;

  PacketType type() const override { return m_tag.m_packet_type; }
  uint32_t length() const override { return m_length.m_length; }
};

}  // namespace NeoPG
