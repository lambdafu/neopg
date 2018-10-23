// OpenPGP image attribute subpacket (implementation)
// Copyright 2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/openpgp/user_attribute/subpacket/image_attribute_subpacket.h>

#include <neopg/intern/cplusplus.h>
#include <neopg/intern/pegtl.h>

using namespace NeoPG;

namespace NeoPG {
namespace image_attribute_subpacket {

using namespace pegtl;

// Grammar
struct image : rep_max_any<ImageAttributeSubpacket::MAX_LENGTH> {};
struct header_tail : bytes<12> {};
struct header_encoding : any {};
struct header_version : uint8::one<0x01> {};
struct header_size : seq<uint8::one<0x10>, uint8::one<0x00>> {};
struct header : seq<header_size, header_version, header_encoding, header_tail> {
};
struct grammar : must<header, image, eof> {};

// Action
template <typename Rule>
struct action : nothing<Rule> {};

template <>
struct action<header_encoding> {
  template <typename Input>
  static void apply(const Input& in, ImageAttributeSubpacket& packet) {
    packet.m_encoding = static_cast<ImageEncoding>(in.peek_byte(0));
  }
};

template <>
struct action<image> : bind<ImageAttributeSubpacket, std::vector<uint8_t>,
                            &ImageAttributeSubpacket::m_image> {};

template <>
struct action<header_tail> : bind<ImageAttributeSubpacket, std::vector<uint8_t>,
                                  &ImageAttributeSubpacket::m_tail> {};

// Control
template <typename Rule>
struct control : pegtl::normal<Rule> {
  static const std::string error_message;

  template <typename Input, typename... States>
  static void raise(const Input& in, States&&...) {
    throw parser_error(error_message, in);
  }
};

// Unreachable, because rep_max_any always succeeds. But pegtl does not know
// that, so add an error message to silence a compiler warning/error.
template <>
const std::string control<image>::error_message =
    "image attribute subpacket is invalid";

template <>
const std::string control<header>::error_message =
    "image attribute subpacket header is invalid";

template <>
const std::string control<eof>::error_message =
    "image attribute subpacket is too large";

}  // namespace image_attribute_subpacket
}  // namespace NeoPG

std::unique_ptr<ImageAttributeSubpacket>
ImageAttributeSubpacket::create_or_throw(ParserInput& in) {
  auto data = make_unique<ImageAttributeSubpacket>();
  pegtl::parse<image_attribute_subpacket::grammar,
               image_attribute_subpacket::action,
               image_attribute_subpacket::control>(in.m_impl->m_input,
                                                   *data.get());
  return data;
}

void ImageAttributeSubpacket::write_body(std::ostream& out) const {
  // Little-endian image header length ("historical accident").
  out << static_cast<uint8_t>(0x10) << static_cast<uint8_t>(0x00);
  // Image header version.
  out << static_cast<uint8_t>(0x01);
  // Encoding.
  out << static_cast<uint8_t>(m_encoding);
  // Reserved.
  if (m_tail.size() == 12)
    out.write(reinterpret_cast<const char*>(m_tail.data()), m_tail.size());
  else
    out << std::string(12, '\x00');

  out.write(reinterpret_cast<const char*>(m_image.data()), m_image.size());
}
