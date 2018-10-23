// OpenPGP raw user attribute subpacket
// Copyright 2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#pragma once

#include <neopg/openpgp/user_attribute/user_attribute_subpacket.h>

#include <neopg/parser/parser_input.h>

#include <memory>
#include <vector>

namespace NeoPG {

/// User attribute subpacket for unknown type.
class NEOPG_UNSTABLE_API RawUserAttributeSubpacket
    : public UserAttributeSubpacket {
 public:
  /// The subpacket type.
  UserAttributeSubpacketType m_type{UserAttributeSubpacketType::Reserved_0};

  /// The content.
  std::vector<uint8_t> m_content;

  /// The parser limit for the size of #m_content. Any packet larger than that
  /// will cause a ParserError.
  static const size_t MAX_LENGTH = 2048;

  /// Create new raw user attribute subpacket from \p input. Throw an exception
  /// on error.
  ///
  /// \param type the user attribute subpacket type
  /// \param input the parser input to read from
  ///
  /// \return pointer to packet
  ///
  /// \throws ParserError
  static std::unique_ptr<RawUserAttributeSubpacket> create_or_throw(
      UserAttributeSubpacketType type, ParserInput& input);

  /// Return the user attribute subpacket type.
  ///
  /// \return the user attribute subpacket type
  UserAttributeSubpacketType type() const noexcept override { return m_type; };

  /// Write the user attribute subpacket to the output stream.
  ///
  /// \param out the output stream to write to
  void write_body(std::ostream& out) const override;
};

}  // namespace NeoPG
