// OpenPGP user attribute subpacket
// Copyright 2017-2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#pragma once

#include <neopg/utils/common.h>
#include <neopg/parser/parser_input.h>

#include <cstdint>
#include <memory>
#include <ostream>

namespace NeoPG {

/// Represent an OpenPGP [user attribute subpacket length
/// type](https://tools.ietf.org/html/rfc4880#section-5.12).
enum class NEOPG_UNSTABLE_API UserAttributeSubpacketLengthType : uint8_t {
  OneOctet = 0,
  TwoOctet = 1,
  FiveOctet = 2,

  /// This picks the best encoding automatically.
  Default
};

/// Represent an OpenPGP [user attribute subpacket
/// length](https://tools.ietf.org/html/rfc4880#section-5.12)
class NEOPG_UNSTABLE_API UserAttributeSubpacketLength {
 public:
  UserAttributeSubpacketLengthType m_length_type;
  uint32_t m_length;

  static void verify_length(uint32_t length,
                            UserAttributeSubpacketLengthType length_type);

  static UserAttributeSubpacketLengthType best_length_type(uint32_t length);

  void set_length(uint32_t length,
                  UserAttributeSubpacketLengthType length_type =
                      UserAttributeSubpacketLengthType::Default);

  UserAttributeSubpacketLength(uint32_t length,
                               UserAttributeSubpacketLengthType length_type =
                                   UserAttributeSubpacketLengthType::Default);

  void write(std::ostream& out);
};

/// Representation of an OpenPGP [user attribute subpacket
/// type](https://tools.ietf.org/html/rfc4880#section-5.12).
enum class NEOPG_UNSTABLE_API UserAttributeSubpacketType : uint8_t {
  Reserved_0 = 0x00,
  Image = 0x01,
  Private_100 = 0x64,
  Private_101 = 0x65,
  Private_102 = 0x66,
  Private_103 = 0x67,
  Private_104 = 0x68,
  Private_105 = 0x69,
  Private_106 = 0x6a,
  Private_107 = 0x6b,
  Private_108 = 0x6c,
  Private_109 = 0x6d,
  Private_110 = 0x6e,
};

/// Representation of an OpenPGP [user
/// attribute](https://tools.ietf.org/html/rfc4880#section-5.12) packet.
class NEOPG_UNSTABLE_API UserAttributeSubpacket {
 public:
  /// Create new user attribute subpacket from \p input. Throw an exception on
  /// error.
  ///
  /// \param type the user attribute subpacket type
  /// \param input the parser input to read from
  ///
  /// \return pointer to packet
  ///
  /// \throws ParserError
  static std::unique_ptr<UserAttributeSubpacket> create_or_throw(
      UserAttributeSubpacketType type, ParserInput& in);

  /// Use this to overwrite the default length (including the type field).
  std::unique_ptr<UserAttributeSubpacketLength> m_length;

  /// Write the subpacket to \p out. If \p m_length is set, use that. Otherwise,
  /// generate a default header using the provided length type.
  void write(std::ostream& out,
             UserAttributeSubpacketLengthType length_type =
                 UserAttributeSubpacketLengthType::Default) const;

  /// Write the body of the subpacket to \p out.
  ///
  /// @param out The output stream to which the body is written.
  virtual void write_body(std::ostream& out) const = 0;

  /// Return the length of the subpacket.
  uint32_t body_length() const;

  /// Return the subpacket type.
  ///
  /// \return the type of the subpacket.
  virtual UserAttributeSubpacketType type() const noexcept = 0;

  // Prevent memory leak when upcasting in smart pointer containers.
  virtual ~UserAttributeSubpacket() = default;
};

}  // namespace NeoPG
