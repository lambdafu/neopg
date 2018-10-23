// OpenPGP image attribute subpacket
// Copyright 2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#pragma once

#include <neopg/openpgp/user_attribute/user_attribute_subpacket.h>

#include <neopg/parser/parser_input.h>

#include <memory>
#include <vector>

namespace NeoPG {

/// Representation of an OpenPGP Image Encoding.
enum class NEOPG_UNSTABLE_API ImageEncoding : uint8_t {
  JPEG = 0x01,
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

/// Representation of an OpenPGP
/// [image attribute](https://tools.ietf.org/html/rfc4880#section-5.12.1)
/// subpacket.
class NEOPG_UNSTABLE_API ImageAttributeSubpacket
    : public UserAttributeSubpacket {
 public:
  /// The subpacket type.
  ImageEncoding m_encoding{ImageEncoding::JPEG};

  /// The content.
  std::vector<uint8_t> m_image;

  /// The header tail (should be all zero, but sometimes isn't).
  std::vector<uint8_t> m_tail;

  /// The parser limit for the size of #m_image. Any packet larger than that
  /// will cause a ParserError.
  static const size_t MAX_LENGTH = 1024 * 1024;

  /// Create new image attribute subpacket from \p input. Throw an exception
  /// on error.
  ///
  /// \param input the parser input to read from
  ///
  /// \return pointer to packet
  ///
  /// \throws ParserError
  static std::unique_ptr<ImageAttributeSubpacket> create_or_throw(
      ParserInput& input);

  /// Return the user attribute subpacket type.
  ///
  /// \return the the value UserAttributeSubpacketType::Image
  UserAttributeSubpacketType type() const noexcept override {
    return UserAttributeSubpacketType::Image;
  };

  /// Write the user attribute subpacket to the output stream.
  ///
  /// \param out the output stream to write to
  void write_body(std::ostream& out) const override;
};

}  // namespace NeoPG
