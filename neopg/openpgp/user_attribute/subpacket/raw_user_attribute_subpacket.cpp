// OpenPGP raw user attribute subpacket (implementation)
// Copyright 2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/openpgp/user_attribute/subpacket/raw_user_attribute_subpacket.h>

#include <neopg/intern/cplusplus.h>
#include <neopg/intern/pegtl.h>

using namespace NeoPG;

namespace NeoPG {
namespace raw_user_attribute_subpacket {

using namespace pegtl;

// Grammar
struct content : rep_max_any<RawUserAttributeSubpacket::MAX_LENGTH> {};
struct grammar : must<content, eof> {};

// Action

template <typename Rule>
struct action : nothing<Rule> {};

template <>
struct action<content> : bind<RawUserAttributeSubpacket, std::vector<uint8_t>,
                              &RawUserAttributeSubpacket::m_content> {};

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
const std::string control<content>::error_message =
    "raw user attribute subpacket is invalid";

template <>
const std::string control<eof>::error_message =
    "raw user attribute subpacket is too large";

}  // namespace raw_user_attribute_subpacket
}  // namespace NeoPG

std::unique_ptr<RawUserAttributeSubpacket>
RawUserAttributeSubpacket::create_or_throw(UserAttributeSubpacketType type,
                                           ParserInput& in) {
  auto data = make_unique<RawUserAttributeSubpacket>();
  data->m_type = type;
  pegtl::parse<raw_user_attribute_subpacket::grammar,
               raw_user_attribute_subpacket::action,
               raw_user_attribute_subpacket::control>(in.m_impl->m_input,
                                                      *data.get());
  return data;
}

void RawUserAttributeSubpacket::write_body(std::ostream& out) const {
  out.write(reinterpret_cast<const char*>(m_content.data()), m_content.size());
}
